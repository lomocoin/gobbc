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
	Addr  string
	Privk string
	Pubk  string
}

// MakeKeyPair .
func MakeKeyPair() (AddrKeyPair, error) {
	var pair AddrKeyPair
	pubk, privk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return pair, err
	}

	pair.Pubk = CopyReverseThenEncodeHex(pubk)
	pair.Privk = CopyReverseThenEncodeHex(privk.Seed())

	addr, err := GetPubKeyAddress(pair.Pubk)
	if err != nil {
		return pair, err
	}
	pair.Addr = addr
	return pair, nil
}

// Seed2string 私钥字符串
func Seed2string(seed []byte) string {
	return CopyReverseThenEncodeHex(seed)
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
	M, N    uint8 //m-n签名,N名成员需要至少M个签名
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

// GetPubKeyAddress Get Address hex string from public key hex string
func GetPubKeyAddress(pubk string) (string, error) {
	var ui uint256
	uint256SetHex(&ui, pubk)
	return "1" + Base32Encode(ui[:]), nil
}
