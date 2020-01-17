package gobbc

import (
	"encoding/hex"
	"encoding/json"
)

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
	Prefix          uint8    //addr prefix
	AddressBytes    [32]byte `json:"-"` // binary data (caller do not care about this field, you just care hex field)
	Amount          int64
	TxFee           int64
	SizeOut         uint8
	VchData         []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
	SizeSign        uint64 // binary sign data size, ref: https://github.com/bigbangcore/BigBang/wiki/IO-Stream#stdvector-stdmap-stdstring
	SignBytes       []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
}

// Transaction . TODO 增加vout
type Transaction struct {
	RawTransaction
	HashAnchor string // hex string([65]byte)
	Address    string // hex string ([64 + 1]byte)
	Sign       string // hex string
}

// MultisigTXData .
type MultisigTXData struct {
	TplHex string `json:"tpl_hex,omitempty"` //成员信息,通过rpc validateaddress (多签模版地址) 取到的值的ret.Addressdata.Templatedata.Hex
	TxHex  string `json:"tx_hex,omitempty"`  //encoded tx data
}

// ToJSONHex json marshal + hex encode
func (data *MultisigTXData) ToJSONHex() (string, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// FromJSONHex parse jsonHex set value to data
func (data *MultisigTXData) FromJSONHex(jsonHex string) error {
	b, err := hex.DecodeString(jsonHex)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, data)
}
