package gobbc

import (
	"encoding/binary"
	"encoding/hex"
)

// UntilError execute all func until error returned
func UntilError(fns ...func() error) error {
	for _, fn := range fns {
		if e := fn(); e != nil {
			return e
		}
	}
	return nil
}

// CopyReverse copy and reverse []byte
func CopyReverse(bs []byte) []byte {
	s := make([]byte, len(bs))
	copy(s, bs)
	return reverseBytes(s)
}

// reverseBytes reverse []byte s, and return s
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// CopyReverseThenEncodeHex 复制[]byte,反转后hex.EncodeToString
func CopyReverseThenEncodeHex(bs []byte) string {
	return hex.EncodeToString(CopyReverse(bs))
}

// GetTemplateType 如果解析失败则返回TemplateTypeMin(0)
func GetTemplateType(templateData string) TemplateType {
	b, err := hex.DecodeString(templateData[:4])
	if err != nil {
		return TemplateTypeMin
	}
	v := binary.LittleEndian.Uint16(b)
	return TemplateType(v)
}
