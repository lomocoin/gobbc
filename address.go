package gobbc

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
)

//some len const
const (
	PubkeyHexLen     = 32*2 + 1
	PrivkeyHexLen    = 32*2 + 1
	PubkeyAddressLen = 57 + 1
	Uint256HexLen    = 65
)

// AddrKeyPair 地址、私钥、公钥
type AddrKeyPair struct {
	Privk string
	Pubk  string
	Addr  string
}

// MakeKeyPair .
func MakeKeyPair() (AddrKeyPair, error) {
	var pair AddrKeyPair
	pubk, privk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return pair, err
	}

	pair.Pubk = hex.EncodeToString(CopyReverse(pubk))
	pair.Privk = hex.EncodeToString(CopyReverse(privk.Seed()))

	addr, err := GetPubKeyAddress(pair.Pubk)
	if err != nil {
		return pair, err
	}
	pair.Addr = addr
	return pair, nil
}

// Seed2string 私钥字符串
func Seed2string(seed []byte) string {
	return hex.EncodeToString(CopyReverse(seed))
}

// Seed2pubk .
func Seed2pubk(seed []byte) ([]byte, error) {
	if l := len(seed); l != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed len, %v", l)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), nil
}

// Seed2pubkString .
func Seed2pubkString(seed []byte) (string, error) {
	pubk, err := Seed2pubk(seed)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(reverseBytes(pubk)), nil
}

// PrivateKeyHex2Seed 解析私钥为实际使用的seed
func PrivateKeyHex2Seed(hexedPrivk string) ([]byte, error) {
	b, err := hex.DecodeString(hexedPrivk)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode private key, %v", err)
	}
	return reverseBytes(b), nil
}

// ParsePublicKeyHex 解析私钥为实际使用的seed
func ParsePublicKeyHex(hexedPubK string) ([]byte, error) {
	b, err := hex.DecodeString(hexedPubK)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode private key, %v", err)
	}
	return reverseBytes(b), nil
}

// MultisigInfo 多签信息
type MultisigInfo struct {
	Hex     string
	M, N    uint8 //m-n签名(权重)
	Members []MultisigMember
}

// MultisigMember .
type MultisigMember struct {
	Pub    []byte
	Weight uint8
}

// SignTemplatePart 签名时签名的前半部分
func (mi MultisigInfo) SignTemplatePart() []byte {
	b, _ := hex.DecodeString(mi.Hex[4:])
	return b
}

// Pubks 参与签名的公钥列表
func (mi MultisigInfo) Pubks() [][]byte {
	var pubks [][]byte
	for _, m := range mi.Members {
		pubks = append(pubks, m.Pub)
	}
	return pubks
}

// ParseMultisigTemplateHex 解析多签地址hex，
// hex decode
// 前2byte代表类型，通常是0200 (不确定是0200或者0020)
// 接下来1+8 byte为M,N
// 接下来有N个33 (32为公钥,1为weight)
// ref to: https://github.com/bigbangcore/BigBang/wiki/%E5%A4%9A%E9%87%8D%E7%AD%BE%E5%90%8D
// |---2---|---1---|---8---|---33*n---|
// |  type |    M  |    N  |  keys... |
func ParseMultisigTemplateHex(hexData string) (*MultisigInfo, error) {
	b, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, fmt.Errorf("invalid hex, %v", err)
	}

	// 长度校验
	l := len(b)
	if l < 44 || (l-11)%33 != 0 {
		return nil, fmt.Errorf("hex template data 长度似乎异常，不符合 2 + 1 + 8 + 33n 模式, %v", l)
	}

	info := MultisigInfo{
		Hex: hexData,
		M:   uint8(b[2]),
	}

	count := 0
	b = b[11:] // 2+1+8
	for ; len(b) > 0; b = b[33:] {
		b33 := b[:33]
		info.Members = append(info.Members, MultisigMember{
			Pub: b33[:32], Weight: uint8(b33[32]),
		})
		count++
	}
	info.N = uint8(count)
	return &info, nil
}

// ParsePrivkHex BBC 私钥解析为ed25519.PrivateKey
func ParsePrivkHex(privkHex string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(privkHex)
	if err != nil {
		return nil, err
	}
	seed := CopyReverse(b)
	if l := len(seed); l != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519: bad seed length: %d", l)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Address2pubk addr => public key
func Address2pubk(pubk string) (string, error) {
	return "TBD", nil
}

// GetPubKeyAddress Get Address hex string from public key hex string
func GetPubKeyAddress(pubk string) (string, error) {
	var ui uint256
	uint256SetHex(&ui, pubk)
	return "1" + Base32Encode(ui[:]), nil
}

func IsValidAddress(addr string) bool {
	// TODO
	return false
}
