package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/blake2b"
	"log"
	"unsafe"
)

func DecodeRawTransaction(txData string, decodeSignData bool) (*Transaction, error) {
	rtx, err := txDeserialize(txData, decodeSignData)
	if err != nil {
		return nil, err
	}
	tx := Transaction{RawTransaction: *rtx}
	tx.HashAnchor = hex.EncodeToString(CopyReverse(tx.HashAnchorBytes[:]))
	tx.Address, _ = GetPubKeyAddress(hex.EncodeToString(CopyReverse(tx.AddressBytes[:])))
	if decodeSignData {
		tx.Sign = hex.EncodeToString(tx.SignBytes)
	}
	return &tx, nil
}

func txDeserialize(txData string, decodeSignData bool) (*RawTransaction, error) {
	b, err := hex.DecodeString(txData)
	if err != nil {
		return nil, err
	}

	var errs []error

	tx := new(RawTransaction)
	r := bytes.NewBuffer(b)
	read := func(v interface{}) {
		if e := binary.Read(r, binary.LittleEndian, v); e != nil {
			log.Printf("[ERR]解析tx数据时无法读取到字段: %v(%T)\n", v, v)
			errs = append(errs, e)
		}
	}

	var size int
	read(&tx.Version)
	read(&tx.Typ)
	read(&tx.Timestamp)
	read(&tx.LockUntil)
	copy(tx.HashAnchorBytes[:], r.Next(int(unsafe.Sizeof(tx.HashAnchorBytes))))
	read(&tx.SizeIn)

	size = 33 * int(tx.SizeIn)
	tx.Input = make([]byte, size)
	copy(tx.Input, r.Next(size))

	read(&tx.Prefix)
	copy(tx.AddressBytes[:], r.Next(int(unsafe.Sizeof(tx.AddressBytes))))
	read(&tx.Amount)
	read(&tx.TxFee)
	read(&tx.SizeOut)

	size = int(tx.SizeOut)
	tx.VchData = make([]byte, size)
	copy(tx.VchData, r.Next(size)) //考虑逻辑是什么？。。。是不是直接表示字节数，而不是out的笔数

	if decodeSignData {
		read(&tx.SizeSign)

		size = int(tx.SizeSign)
		tx.SignBytes = make([]byte, size)
		copy(tx.SignBytes, r.Next(size))
	}

	if len(errs) != 0 {
		err = fmt.Errorf("some errors when read binary: %v", errs)
	}
	// TODO vin list
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
		write(rtx.SizeSign)
		buf.Write(rtx.SignBytes)
	} else {
		buf.WriteByte(0) //表示不包含签名数据
	}

	// TODO write outputs,and signs
	// fmt.Println("[dbg] buf.Len()", buf.Len())

	var err error
	if len(errs) != 0 {
		err = fmt.Errorf("some errors when write binary: %v", errs)
	}

	return buf.Bytes(), err
}

// SignWithKey 用私钥签名
func (rtx *RawTransaction) SignWithHexedKey(privkHex string) error {
	privk, err := ParsePrivkHex(privkHex)
	if err != nil {
		return err
	}
	// 1.确认私钥解析一致
	fmt.Println("[dbg] privk(5):", privk[:5])
	b, err := rtx.EncodeBytes(false)
	if err != nil {
		return err
	}
	b = b[:len(b)-1] //TODO 暂时先这么处理，丢弃最后一位，最后一位表示签名长度
	// 2.确认序列化一致
	// fmt.Printf("[dbg] tx encodeBytes(len:%d) 5...18: %v...%v\n", len(b), b[:5], b[len(b)-18:])
	sum := blake2b.Sum256(b)
	// 3.确认hash一致
	// fmt.Printf("[dbg] blake2b: %v\n", sum[:])
	rtx.SignBytes = ed25519.Sign(privk, sum[:])
	// 4.确认签名一致
	// fmt.Printf("[dbg] sig 5...5: %v...%v\n", rtx.SignBytes[:5], rtx.SignBytes[59:])
	rtx.SizeSign = uint8(len(rtx.SignBytes))
	return nil
}

// RawTransaction 实际的序列话数据结构
// 注意：数据类型不要更改（序列化时对类型有依赖）
type RawTransaction struct {
	Version         uint16
	Typ             uint16 //type > typ
	Timestamp       uint32
	LockUntil       uint32
	HashAnchorBytes [32]byte `json:"-"` // binary data (caller do not care about this field, you just care hex field)
	SizeIn          uint8    //input 数量
	Input           []byte   `json:"-"`
	Prefix          uint8
	AddressBytes    [32]byte `json:"-"` // binary data (caller do not care about this field, you just care hex field)
	Amount          int64
	TxFee           int64
	SizeOut         uint8
	VchData         []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
	SizeSign        uint8  // binary sign data size
	SignBytes       []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
}

// Transaction .
type Transaction struct {
	RawTransaction
	HashAnchor string // hex string([65]byte)
	Address    string // hex string ([64 + 1]byte)
	Sign       string // hex string
}
