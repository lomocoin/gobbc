package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

type littleEndianPubks [][]byte //公钥数组小端排序，实现了sort.Interface接口

// Len is the number of elements in the collection.
func (a littleEndianPubks) Len() int { return len(a) }

// Less reports whether the element with index i should sort before the element with index j.
func (a littleEndianPubks) Less(i, j int) bool {
	for x := len(a[0]) - 1; i >= 0; x-- {
		xi, xj := a[i][x], a[j][x]
		if xi < xj {
			return true
		} else if xi > xj {
			return false
		}
	}
	return false
}

// Swap swaps the elements with indexes i and j.
func (a littleEndianPubks) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

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

// CryptoMultiSign pubks 公钥数组，privk 私钥, msg 待签名数据, sig 已有签名
func CryptoMultiSign(pubks [][]byte, privk ed25519.PrivateKey, msg []byte, currentSig []byte) ([]byte, error) {
	sort.Sort(littleEndianPubks(pubks))

	// fmt.Println("[dbg] multisig msg", msg)
	if len(pubks) == 0 {
		return nil, errors.New("no pub keys")
	}

	lenSig := len(currentSig)
	nIndexLen := (len(pubks)-1)/8 + 1
	if lenSig > 0 && (lenSig <= nIndexLen || (lenSig-nIndexLen)%64 != 0) {
		return nil, fmt.Errorf("已有签名长度异常 %d (nIndexLen: %d, l - n mod 64 should be 0)", lenSig, nIndexLen)
	}

	pubk := privk.Public().(ed25519.PublicKey)

	pubkIndex := -1
	for i, pubX := range pubks {
		if bytes.Equal(pubX, pubk) {
			pubkIndex = i
			break
		}
	}
	if pubkIndex == -1 {
		return nil, fmt.Errorf("pubk correspond to privk not found in pubks")
	}

	var indexBitmap []byte
	if lenSig > 0 {
		indexBitmap = currentSig[:nIndexLen]
	} else {
		indexBitmap = make([]byte, nIndexLen)
	}

	if indexBitmap[pubkIndex/8]&(1<<(pubkIndex%8)) == 1 {
		return currentSig, errors.New("已经签过名了")
	}
	//TODO 校验，对于已经签名的数量，长度应该符合x+64m
	signedBytes := ed25519.Sign(privk, msg)
	// fmt.Println("[dbg]signed bytes", signedBytes)
	indexBitmap[pubkIndex/8] |= (1 << (pubkIndex % 8)) // fmt.Println("[bg]indexBitmap", indexBitmap)
	if lenSig == 0 {
		return append(indexBitmap, signedBytes...), nil
	}
	// copy(sig, indexBitmap)
	sigs := currentSig[nIndexLen:]
	// offset
	offset := 0
	for i := 0; i < len(pubks); i++ {
		if i == pubkIndex {
			break
		}
		if indexBitmap[i/8]>>(i%8)%2 == 1 {
			offset++
		}
	}
	offset *= 64

	ret := bytes.Join([][]byte{
		indexBitmap,
		sigs[:offset],
		signedBytes,
		sigs[offset:],
	}, []byte{})

	// fmt.Println("[dbg]offset", offset, hex.EncodeToString(sigs[:offset]), hex.EncodeToString(signedBytes), hex.EncodeToString(sigs[offset:]))
	// fmt.Println("[dbg]sig", hex.EncodeToString(ret))
	return ret, nil
}
