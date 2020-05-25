package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"unsafe"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/blake2b"
)

// DecodeRawTransaction hexed tx parse
func DecodeRawTransaction(txData string, decodeSignData bool) (*Transaction, error) {
	rtx, err := txDeserialize(txData, decodeSignData)
	if err != nil {
		return nil, err
	}
	tx := rtx.ToTransaction(decodeSignData)
	return &tx, nil
}

// ToTransaction .
func (rtx RawTransaction) ToTransaction(includeSignData bool) Transaction {
	tx := Transaction{RawTransaction: rtx}
	tx.HashAnchor = hex.EncodeToString(CopyReverse(tx.HashAnchorBytes[:]))
	tx.Address, _ = GetPubKeyAddress(hex.EncodeToString(CopyReverse(tx.AddressBytes[:])))
	if includeSignData {
		tx.Sign = hex.EncodeToString(tx.SignBytes)
	}
	tx.Data = hex.EncodeToString(tx.VchData)
	cursor := 0
	for i := 0; i < int(tx.SizeIn); i++ {
		tx.Vin = append(tx.Vin, Vin{
			Txid: hex.EncodeToString(CopyReverse(tx.Input[cursor : cursor+32])),
			Vout: int(tx.Input[cursor+32:][0]),
		})
		cursor = cursor + 33
	}
	return tx
}

func txDeserialize(txData string, decodeSignData bool) (*RawTransaction, error) {
	b, err := hex.DecodeString(txData)
	if err != nil {
		return nil, err
	}

	var errs []error

	tx := new(RawTransaction)
	buffer := bytes.NewBuffer(b)
	read := func(v interface{}) {
		if e := binary.Read(buffer, binary.LittleEndian, v); e != nil {
			log.Printf("[ERR]解析tx数据时无法读取到字段: %v(%T)\n", v, v)
			errs = append(errs, e)
		}
	}

	var size int
	read(&tx.Version)
	read(&tx.Typ)
	read(&tx.Timestamp)
	read(&tx.LockUntil)
	copy(tx.HashAnchorBytes[:], buffer.Next(int(unsafe.Sizeof(tx.HashAnchorBytes))))
	read(&tx.SizeIn)

	size = 33 * int(tx.SizeIn)
	tx.Input = make([]byte, size)
	copy(tx.Input, buffer.Next(size))

	read(&tx.Prefix)
	copy(tx.AddressBytes[:], buffer.Next(int(unsafe.Sizeof(tx.AddressBytes))))
	read(&tx.Amount)
	read(&tx.TxFee)
	read(&tx.SizeOut)

	size = int(tx.SizeOut)
	tx.VchData = make([]byte, size)
	copy(tx.VchData, buffer.Next(size)) //考虑逻辑是什么？。。。是不是直接表示字节数，而不是out的笔数

	if decodeSignData {
		sizeFlag, err := buffer.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("unable to read sign size flag: %v", err)
		}
		switch sz := sizeFlag; {
		case sz < 0xfd:
			tx.SizeSign = uint64(sz)
		case sz == 0xfd:
			var size uint16
			read(&size)
			tx.SizeSign = uint64(size)
		case sz == 0xfe:
			var size uint32
			read(&size)
			tx.SizeSign = uint64(size)
		case sz == 0xff:
			read(&tx.SizeSign)
		default:
			return nil, fmt.Errorf("unexpected sig size %d", sz)
		}

		size = int(tx.SizeSign)
		tx.SignBytes = make([]byte, size)
		copy(tx.SignBytes, buffer.Next(size))
	}

	if len(errs) != 0 {
		err = fmt.Errorf("some errors when read binary: %v", errs)
	}
	return tx, err
}

// Encode .
func (rtx *RawTransaction) Encode(encodeSignData bool) (string, error) {
	b, err := rtx.EncodeBytes(encodeSignData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// EncodeBytes .
func (rtx *RawTransaction) EncodeBytes(encodeSignData bool) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	var errs []error

	write := func(v interface{}) {
		if e := binary.Write(buf, binary.LittleEndian, v); e != nil {
			errs = append(errs, e)
		}
	}
	write(rtx.Version)
	write(rtx.Typ)
	write(rtx.Timestamp)
	write(rtx.LockUntil)
	buf.Write(rtx.HashAnchorBytes[:])
	write(rtx.SizeIn)
	buf.Write(rtx.Input) //:33*int(rtx.SizeIn)
	write(rtx.Prefix)
	buf.Write(rtx.AddressBytes[:])
	write(rtx.Amount)
	write(rtx.TxFee)
	write(rtx.SizeOut)
	buf.Write(rtx.VchData)
	if encodeSignData {
		switch sz := rtx.SizeSign; {
		case sz < 0xFD:
			write(uint8(rtx.SizeSign))
		case sz <= 0xffff:
			buf.WriteByte(0xfd)
			write(uint16(rtx.SizeSign))
		case sz <= 0xFFFFFFFF:
			buf.WriteByte(0xfe)
			write(uint32(rtx.SizeSign))
		case sz > 0xFFFFFFFF:
			buf.WriteByte(0xff)
			write(rtx.SizeSign)
		default:
			errs = append(errs, fmt.Errorf("should not here, encode transaction, unexpected sign size: %d", rtx.SizeSign))
		}
		buf.Write(rtx.SignBytes)
	} else {
		buf.WriteByte(0) //表示不包含签名数据
	}

	var err error
	if len(errs) != 0 {
		err = fmt.Errorf("some errors when write binary: %v", errs)
	}
	return buf.Bytes(), err
}

// Txid 计算txid
func (rtx *RawTransaction) Txid() ([32]byte, error) {
	msg, err := rtx.EncodeBytes(false)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode tx to sign msg, %v", err)
	}
	msg = msg[:len(msg)-1]
	// fmt.Println("[dbg] encoded tx bytes:", msg)
	return blake2b.Sum256(msg), nil
}

// SignWithPrivateKey 用私钥签名
// templateDataList: 使用[,]分隔的模版数据列表，
// - 对于不需要模版数据的交易传入空字符串即可，
// - 如果传入了模版数据签名后会将模版数据按照顺序放在签名前面，
// - 如果传入的模版数据检测到多重签名则在签名时使用多重签名机制
//
// 通常，在from为模版地址时需要传入from的模版数据，可以通过rpc validateaddress 获取(data.addressdata.templatedata.hex)
// 当to地址为vote类型模版地址时需要传入to地址模版数据
// 特别的，只有1种情况需要传入2个模版地址：delegate类型模版的owner为多签地址，从该地址转出时需要传入：delegate模版数据,多签模版数据
// （基于上面一种情况，如果转出地址为vote template可能还需要提供vote template data, 一共3个😂，这个未经测试、验证）
//
// 下面列出常见的场景：
// 一般公钥地址转出(到非vote template)->(不需要模版数据)
// 一般公钥地址投票时->投票模版数据
// 一般公钥投票赎回时->投票模版数据
// 多签地址签名（转账到一般地址)->多签模版数据
// 从dpos委托模版地址转出->委托模版数据
// 从dpos委托模版(owner为多签)地址转出->委托模版数据+多签模版数据
// 从pow挖矿模版地址转出->pow挖矿模版地址
//
// 注意：签名逻辑不对模版数据进行严格合理的校验，因为离线环境下无法感知模版数据的有效性，调用方需自行确保参数正确
func (rtx *RawTransaction) SignWithPrivateKey(templateDataList, privkHex string) error {
	var rawTemplateBytes []byte //移除每个模版的前2个byte（类型说明），并join
	var multisigTemplateData string

	for _, tpl := range strings.Split(templateDataList, TemplateDataSpliter) {
		if len(tpl) == 0 {
			continue
		}
		_b, err := hex.DecodeString(tpl)
		if err != nil {
			return fmt.Errorf("unable to decode template data: %v", err)
		}
		rawTemplateBytes = append(rawTemplateBytes, _b[2:]...) //前2位为模版类型
		if GetTemplateType(tpl) == TemplateTypeMultisig {
			multisigTemplateData = tpl
		}
	}

	if multisigTemplateData == "" && len(rtx.SignBytes) > 0 { //非多签确已经有签名数据了
		return errors.New("seems tx already signed")
	}
	privk, err := ParsePrivkHex(privkHex)
	if err != nil {
		return fmt.Errorf("unable to parse private key from hex data")
	}
	txid, err := rtx.Txid()
	if err != nil {
		return fmt.Errorf("calculate txid failed, %v", err)
	}

	if multisigTemplateData == "" { //单签
		sigBytes := ed25519.Sign(privk, txid[:])
		if len(rawTemplateBytes) > 0 {
			rtx.SignBytes = append(rawTemplateBytes, sigBytes...)
		} else {
			rtx.SignBytes = sigBytes
		}
		rtx.SizeSign = uint64(len(rtx.SignBytes))
		return nil
	}

	// 对于多重签名，首次签名时签名数据应该为空
	// 非首次签名时，应包含模版数据和已有签名数据，模版数据应该以传入的为准并且和已有的签名模版数据一致
	// 每个私钥签名时，重新拼装签名数据
	var sigPart []byte
	_ls, _lt := len(rtx.SignBytes), len(rawTemplateBytes)
	if _ls > 0 { //已有签名数据
		// 首先检查签名数据中的模版数据与传入的模版数据一致
		if _ls < _lt {
			return fmt.Errorf("多签数据检查异常，现有签名长度(%d)小于传入的模版长度(%d)", _ls, _lt)
		}
		if !bytes.Equal(rawTemplateBytes, rtx.SignBytes[:_lt]) {
			return fmt.Errorf("多签数据检查异常，现有签名模版数据与传入的不一致")
		}
		sigPart = make([]byte, _ls-_lt)
		copy(sigPart, rtx.SignBytes[_lt:])
	}
	// 含多签的签名结构: | 模版数据 | 成员签名 ｜

	multisigInfo, err := ParseMultisigTemplateHex(multisigTemplateData)
	if err != nil {
		return fmt.Errorf("failed to parse multisig template data, %v", err)
	}
	sig, err := CryptoMultiSign(multisigInfo.Pubks(), privk, txid[:], sigPart)
	if err != nil {
		return fmt.Errorf("CryptoMultiSign error, %v", err)
	}
	rtx.SignBytes = append(rawTemplateBytes, sig...)
	rtx.SizeSign = uint64(len(rtx.SignBytes))
	return nil
}

// TXBuilder .
type TXBuilder struct {
	rtx *RawTransaction
	err error
}

func NewTXBuilder() *TXBuilder {
	return &TXBuilder{
		rtx: &RawTransaction{
			Version: 1,
			Typ:     0, //token

		},
	}
}

// return b.err != nil
func (b *TXBuilder) setErr(e error) bool {
	if b.err == nil {
		b.err = e
	}
	return b.err != nil
}

// SetAnchor 锚定分支id
func (b *TXBuilder) SetAnchor(anchor string) *TXBuilder {
	bytes, err := hex.DecodeString(anchor)
	if err != nil {
		b.setErr(fmt.Errorf("hex decode anchor failed, %v", err))
		return b
	}
	if len(bytes) != 32 {
		b.setErr(fmt.Errorf("%s 似乎不是合法的 anchor,长度不是32", anchor))
		return b
	}
	copy(b.rtx.HashAnchorBytes[:], reverseBytes(bytes))
	return b
}

// SetTimestamp 当前时间戳
func (b *TXBuilder) SetTimestamp(timestamp int) *TXBuilder {
	b.rtx.Timestamp = uint32(timestamp)
	return b
}

// SetLockUntil lock until
func (b *TXBuilder) SetLockUntil(lockUntil int) *TXBuilder {
	b.rtx.LockUntil = uint32(lockUntil)
	return b
}

// SetVersion 当前版本 1
func (b *TXBuilder) SetVersion(v int) *TXBuilder {
	b.rtx.Version = uint16(v)
	return b
}

// AddInput 参考listunspent,确保输入金额满足amount
func (b *TXBuilder) AddInput(txid string, vout uint8) *TXBuilder {
	bytes, err := hex.DecodeString(txid)
	if err != nil {
		b.setErr(fmt.Errorf("%s 似乎不是合法的txid, %v", txid, err))
		return b
	}
	b.rtx.SizeIn++
	input := append(reverseBytes(bytes), vout)
	b.rtx.Input = append(b.rtx.Input, input...)
	return b
}

// SetAddress 转账地址,目前只支持公钥地址
func (b *TXBuilder) SetAddress(add string) *TXBuilder {
	pubk, err := ConvertAddress2pubk(add)
	if b.setErr(err) {
		return b
	}
	bytes, err := hex.DecodeString(pubk)
	if b.setErr(err) {
		return b
	}
	b.rtx.Prefix = 1 //1: pubk address
	copy(b.rtx.AddressBytes[:], reverseBytes(bytes))
	return b
}

// SetAmount 转账金额
func (b *TXBuilder) SetAmount(amount float64) *TXBuilder {
	if amount < 0 {
		b.setErr(fmt.Errorf("amount should be greater than 0"))
		return b
	}
	b.rtx.Amount = decimal.NewFromFloat(amount).Mul(decimal.NewFromInt(Precision)).IntPart()
	return b
}

// SetFee 手续费，目前0.01，如果带data则0.03, 额外需咨询BBC
func (b *TXBuilder) SetFee(fee float64) *TXBuilder {
	if fee < 0 {
		b.setErr(fmt.Errorf("amount should be greater than 0"))
		return b
	}
	b.rtx.TxFee = decimal.NewFromFloat(fee).Mul(decimal.NewFromInt(Precision)).IntPart()
	return b
}

// SetData 原始data设置,参考 UtilDataEncoding
func (b *TXBuilder) SetData(data []byte) *TXBuilder {
	b.rtx.SizeOut = uint8(len(data))
	b.rtx.VchData = data
	return b
}

// SetDataWithUUID 指定uuid,timestamp,data
func (b *TXBuilder) SetDataWithUUID(_uuid string, timestamp int64, data string) *TXBuilder {
	_id, err := uuid.Parse(_uuid)
	if err != nil {
		b.setErr(errors.Wrap(err, "parse uuid failed"))
		return b
	}

	timeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(timeBytes, uint32(timestamp))

	_data, err := hex.DecodeString(strings.Join([]string{
		strings.Replace(_id.String(), "-", "", -1),
		hex.EncodeToString(timeBytes),
		"00",
		hex.EncodeToString([]byte(data)),
	}, ""))
	if err != nil {
		b.setErr(errors.Wrap(err, "hex decode data err"))
		return b
	}
	b.rtx.SizeOut = uint8(len(_data))
	b.rtx.VchData = _data
	return b
}

// SetStringData 自动编码数据,自动生成uuid和时间戳
func (b *TXBuilder) SetStringData(data string) *TXBuilder {
	data = UtilDataEncoding(data)
	bytes, err := hex.DecodeString(data)
	if err != nil {
		b.setErr(errors.Wrap(err, "encoding data err"))
	}
	b.rtx.VchData = bytes
	b.rtx.SizeOut = uint8(len(bytes))
	return b
}

// Build .
func (b *TXBuilder) Build() (*RawTransaction, error) {
	if b.rtx.SizeIn == 0 {
		return nil, errors.New("no input provided")
	}
	if b.rtx.Amount == 0 {
		return nil, errors.New("amount not set")
	}
	if b.rtx.TxFee == 0 {
		return nil, errors.New("tx fee not set")
	}

	noZeroFound := true
	for i := 0; i < 32; i++ {
		if b.rtx.HashAnchorBytes[i] != 0 {
			noZeroFound = false
			break
		}
	}
	if noZeroFound {
		return nil, errors.New("fork id not provided")
	}
	if b.err != nil {
		return nil, b.err
	}
	return b.rtx, nil
}
