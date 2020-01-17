package gobbc

import (
	"bytes"
	"crypto/ed25519"
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

// CryptoMultiSign pubks 公钥数组，privk 私钥, msg 待签名数据, sig 已有签名
func CryptoMultiSign(pubks [][]byte, privk []byte, msg []byte, sig []byte) ([]byte, error) {
	sort.Sort(littleEndianPubks(pubks))

	// fmt.Println("[dbg] multisig msg", msg)
	if len(pubks) == 0 {
		return nil, errors.New("no pub keys")
	}

	lenSig := len(sig)
	nIndexLen := (len(pubks)-1)/8 + 1
	if lenSig > 0 && (lenSig <= nIndexLen || (lenSig-nIndexLen)%64 != 0) {
		return nil, fmt.Errorf("已有签名长度异常 %d (nIndexLen: %d, l - n mod 64 should be 0)", lenSig, nIndexLen)
	}

	pubk := ed25519.NewKeyFromSeed(privk).Public().(ed25519.PublicKey)

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
		indexBitmap = sig[:nIndexLen]
	} else {
		indexBitmap = make([]byte, nIndexLen)
	}

	if indexBitmap[pubkIndex/8]&(1<<(pubkIndex%8)) == 1 {
		return sig, errors.New("已经签过名了")
	}
	//TODO 校验，对于已经签名的数量，长度应该符合x+64m
	signedBytes := ed25519.Sign(ed25519.NewKeyFromSeed(privk), msg)
	// fmt.Println("[dbg]signed bytes", signedBytes)
	indexBitmap[pubkIndex/8] |= (1 << (pubkIndex % 8)) // fmt.Println("[bg]indexBitmap", indexBitmap)
	if lenSig == 0 {
		return append(indexBitmap, signedBytes...), nil
	}
	// copy(sig, indexBitmap)
	sigs := sig[nIndexLen:]
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
	// ret := indexBitmap
	// ret = append(ret, sigs[:offset]...)
	// ret = append(ret, signedBytes...)
	// ret = append(ret, sigs[offset:]...)

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
