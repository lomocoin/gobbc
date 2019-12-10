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

func GetPubKeyFromAddress(pubk string) (string, error) {
	return "TBD", nil
}

func GetAddressFromPubKey(pubk string) (string, error) {
	b := make([]byte, len(pubk))
	copy(b, pubk)
	return hex.EncodeToString(b), nil
}

// GetPubKeyAddress Get Address hex string from public key hex string
func GetPubKeyAddress(pubk string) (string, error) {
	var ui uint256
	uint256SetHex(&ui, pubk)
	// fmt.Println("after set u256:")
	// for i := 0; i < 32; i++ {
	// 	if i%8 == 0 {
	// 		fmt.Println()
	// 	}
	// 	c := ui[i]
	// 	fmt.Printf("%d => %d; ", i, c)
	// }
	// fmt.Println()
	return "1" + Base32Encode(ui[:]), nil
}

func IsValidAddress(addr string) bool {
	// TODO
	return false
}
