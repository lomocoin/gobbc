package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

// DecodeRawTransaction hexed tx parse
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
		sizeFlag, err := r.ReadByte()
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
		copy(tx.SignBytes, r.Next(size))
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

// Multisig .
func (rtx *RawTransaction) Multisig(multisigAddrHex string, privk []byte) error {
	multisigInfo, err := ParseMultisigTemplateHex(multisigAddrHex)
	if err != nil {
		return fmt.Errorf("failed to parse multisig template hex, %v", err)
	}

	txid, err := rtx.Txid()
	if err != nil {
		return fmt.Errorf("failed to calc txid: %v", err)
	}

	var currentSig []byte
	if len(rtx.SignBytes[:]) > 0 {
		tplPartLen := len(multisigInfo.SignTemplatePart())
		currentSig = make([]byte, len(rtx.SignBytes)-tplPartLen)
		copy(currentSig, rtx.SignBytes[tplPartLen:])
	}

	b, err := CryptoMultiSign(multisigInfo.Pubks(), privk, txid[:], currentSig)
	if err != nil {
		return fmt.Errorf("failed to multisign, %v", err)
	}

	// fmt.Println("[dbg]CryptoMultiSIgn:", hex.EncodeToString(b))
	rtx.SignBytes = append(multisigInfo.SignTemplatePart(), b...)
	rtx.SizeSign = uint64(len(rtx.SignBytes))
	return nil
}

// SignWithHexedKey 用私钥签名
func (rtx *RawTransaction) SignWithHexedKey(privkHex string) error {
	if len(rtx.SignBytes) > 0 {
		return errors.New("seems tx already signed")
	}
	privk, err := ParsePrivkHex(privkHex)
	if err != nil {
		return err
	}
	// 1.确认私钥解析一致
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
	rtx.SizeSign = uint64(len(rtx.SignBytes))
	return nil
}
