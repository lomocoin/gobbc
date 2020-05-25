package gobbc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
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

// DataDetail .
type DataDetail struct {
	UUID     string
	UnixTime uint32
	Data     string
}

// UtilDataEncoding 将tx data 进行编码
func UtilDataEncoding(data string) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(time.Now().Unix()))

	return strings.Join([]string{
		strings.Replace(uuid.New().String(), "-", "", -1),
		hex.EncodeToString(b),
		"00",
		hex.EncodeToString([]byte(data)),
	}, "")
}

// UtilDataDecoding .
func UtilDataDecoding(data string) (DataDetail, error) {
	var dd DataDetail
	if l := len(data); l < 32+8+2 {
		return dd, fmt.Errorf("invalid len: %d, should > 42", l)
	}
	dd.UUID = data[:32]

	timeBytes, err := hex.DecodeString(data[32 : 32+8])
	if err != nil {
		return dd, fmt.Errorf("unable to decode time, %v", err)
	}
	dd.UnixTime = binary.LittleEndian.Uint32(timeBytes)

	content, err := hex.DecodeString(data[42:])
	if err != nil {
		return dd, fmt.Errorf("unable to decode content, %v", err)
	}
	dd.Data = string(content)
	return dd, nil
}
