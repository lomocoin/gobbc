package gobbc

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
	SizeSign        uint8  // binary sign data size
	SignBytes       []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
}

// Transaction . TODO 增加vout
type Transaction struct {
	RawTransaction
	HashAnchor string // hex string([65]byte)
	Address    string // hex string ([64 + 1]byte)
	Sign       string // hex string
}
