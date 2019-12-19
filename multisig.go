package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding"
	"errors"
	"fmt"
	"sort"

	"go.dedis.ch/kyber/v3"
	"golang.org/x/crypto/blake2b"
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

// CryptoMultiSign pubks 公钥数组，privk 私钥, anchorBytes ,msg 待签名数据, sig 已有签名
func CryptoMultiSign(pubks [][]byte, privk []byte, anchorBytes []byte, msg []byte, sig []byte) ([]byte, error) {
	sort.Sort(littleEndianPubks(pubks))
	anchor := CopyReverse(anchorBytes)

	var errs []error
	addErr := func(e error, errMsg string) {
		if e != nil {
			errs = append(errs, fmt.Errorf("%s, %v", errMsg, e))
		}
	}
	toScalar := func(b []byte, errMsg string) kyber.Scalar {
		s := cv25.Scalar()
		e := s.UnmarshalBinary(b)
		addErr(e, fmt.Sprintf("failed to unmarshal scalar, %s", errMsg))
		// 这里有个问题，暂时先这么处理，是特性不是bug...参考@multisig_test.go#TestEd25519_scalarMarshal
		// TODO,后续确定如果不加这个能不能通过集成测试，并且讨论实际的原因
		b, _ = s.MarshalBinary()
		_ = s.UnmarshalBinary(b)
		return s
	}
	toPoint := func(b []byte, errMsg string) kyber.Point {
		p := cv25.Point()
		e := p.UnmarshalBinary(b)
		addErr(e, fmt.Sprintf("failed to unmarshal point, %s", errMsg))
		// b, _ = p.MarshalBinary()
		// _ = p.UnmarshalBinary(b)
		return p
	}

	if len(pubks) == 0 {
		return nil, errors.New("no pub keys")
	}

	var _R kyber.Point
	var _S kyber.Scalar
	var err error

	nIndexLen := (len(pubks)-1)/8 + 1
	if len(sig) == 0 {
		sig = make([]byte, nIndexLen+64) //index(bitmap) + R(32) + S(32)
	} else {
		if l := len(sig); l != nIndexLen+64 {
			return nil, fmt.Errorf("已有签名长度异常 %d (should be %d)", l, nIndexLen+64)
		} // fmt.Println("_R, _S", sig[nIndexLen:nIndexLen+32], sig[nIndexLen+32:])
		_R = toPoint(sig[nIndexLen:nIndexLen+32], "_R")
		_S = toScalar(sig[nIndexLen+32:], "_S")
	}

	// H(X,apk,M)
	pubk := ed25519.NewKeyFromSeed(privk).Public().(ed25519.PublicKey) //TODO type convert error, bad privk

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

	indexBitmap := sig[:nIndexLen]

	if indexBitmap[pubkIndex/8]&(1<<(pubkIndex%8)) == 1 {
		return sig, errors.New("已经签过名了")
	}
	var _RBytes, _SBytes []byte
	rTmp := blake2b.Sum256(bytes.Join([][]byte{privk, pubk}, nil))
	ri := blake2b.Sum256(bytes.Join([][]byte{rTmp[:], msg}, nil)) // ri = H(H(si,pi),M), // fmt.Println("toScalar前的ri:", ri)

	{ //cal R
		riScalar := toScalar(ri[:], "ri")
		riPoint := cv25.Point().Base().Mul(riScalar, nil)
		if _R == nil {
			_R = riPoint
		} else {
			_R = _R.Add(riPoint, _R) // dbgPrintPoint("加法后的_R(point)", _R)
		}
		_RBytes, err = _R.MarshalBinary() // fmt.Println("[dbg]RBytes??", _RBytes)
		addErr(err, "failed to marshal _R")
	}

	{ //cal S,使用数运算
		apk, err := multiSignApk(pubks, pubks)
		if err != nil {
			return nil, err
		}
		// fmt.Printf("[dbg]detail of hash: \n%v\n%v\n%v\n ", anchor, apk, msg)
		hashXAM := blake2b.Sum256(bytes.Join([][]byte{anchor, apk, msg}, nil)) // fmt.Println("[dbg]hashXAM", hashXAM)
		preApk := append(make([]byte, 32), bytes.Join(pubks, nil)...)
		copy(preApk[:32], pubk)
		hi := blake2b.Sum256(preApk)

		scalarHashXAM := toScalar(hashXAM[:], "hashXAM") // dbgPrintPoint("hashXAMScalar", scalarHashXAM)
		riScalar := toScalar(ri[:], "ri")                // dbgPrintPoint("riScalar", riScalar)
		hiScalar := toScalar(hi[:], "hi")                // dbgPrintPoint("hiScalar", hiScalar)
		siScalar := toScalar(clampPrivKey(privk), "si")  // dbgPrintPoint("siScalar", siScalar)

		tmpSc := scalarHashXAM.Mul(scalarHashXAM, hiScalar)
		tmpSc = tmpSc.Mul(tmpSc, siScalar)
		tmpSc = riScalar.Add(riScalar, tmpSc)

		if _S == nil {
			_S = tmpSc
		} else {
			_S = _S.Add(_S, tmpSc)
		}
		_SBytes, err = _S.MarshalBinary() // fmt.Println("SBytes", _SBytes)
		addErr(err, "failed to marshal _S")
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("multisig failed, some errors, %v", errs)
	}
	indexBitmap[pubkIndex/8] |= (1 << (pubkIndex % 8)) // fmt.Println("[bg]indexBitmap", indexBitmap)
	return bytes.Join([][]byte{indexBitmap, _RBytes, _SBytes}, nil), nil
}

func clampPrivKey(privk []byte) []byte {
	hash := sha512.Sum512(privk)
	hash[0] &= 248
	hash[31] &= 127
	hash[31] |= 64
	return hash[:32] // fmt.Println("[dbg]clampPrivKey", hash);
}

// H(Ai,A1,...,An)*Ai + ... + H(Aj,A1,...,An)*Aj
// setPubKey = [A1 ... An], setPartKey = [Ai ... Aj], 1 <= i <= j <= n
func multiSignApk(setPubKey [][]byte, setPartKey [][]byte) ([]byte, error) {
	vecHash := append(make([]byte, 32), bytes.Join(setPubKey, nil)...)

	toScalar := func(b []byte, errMsg string) kyber.Scalar {
		s := cv25.Scalar()
		_ = s.UnmarshalBinary(b)
		// addErr(e, fmt.Sprintf("failed to unmarshal scalar, %s", errMsg))
		// 这里有个问题，暂时先这么处理，是特性不是bug...参考@multisig_test.go#TestEd25519_scalarMarshal
		// TODO,后续确定如果不加这个能不能通过集成测试，并且讨论实际的原因
		b, _ = s.MarshalBinary()
		_ = s.UnmarshalBinary(b)
		return s
	}

	var apk kyber.Point
	var err error
	for _, key := range setPartKey {
		// fmt.Println("MultiSig[go] 内部循环key:", key)
		copy(vecHash[:32], key)
		hash := blake2b.Sum256(vecHash) // fmt.Println("[dbg] vecHash after CryptoHash:", hash)

		ai := cv25.Point()
		err = ai.UnmarshalBinary(key)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal point from pubkey, %v", err)
		}
		scalarHash := toScalar(hash[:], "failed to xx hash")
		pi := ai.Mul(scalarHash, ai)
		if apk == nil {
			apk = pi
		} else {
			apk = apk.Add(apk, pi)
		}
	}

	apkb, err := apk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal binary apk, %v", err)
	}
	return apkb, nil // fmt.Println("[dbg] apk bytes:", apkb)
}

func dbgPrintPoint(msg string, p encoding.BinaryMarshaler) {
	// b, _ := p.MarshalBinary()
	// fmt.Println("[dbg] ", msg, b)
}
