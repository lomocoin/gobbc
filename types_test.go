package gobbc

import (
	"fmt"
	"testing"
)

func TestJSONData(t *testing.T) {
	w := TW{T: t}

	for _, d := range []TXData{
		{
			TplHex: "02a3,0032",
			TxHex:  "038ab2",
		},
		{
			TplHex: "02a3",
			TxHex:  "038ab2",
		},
		{
			TplHex: "",
			TxHex:  "038ab2",
		},
	} {

		enc, err := d.EncodeString()
		w.Nil(err)
		fmt.Println(enc)

		var dd TXData
		w.Nil(dd.DecodeString(enc))
		w.Equal(d.TplHex, dd.TplHex)
		w.Equal(d.TxHex, dd.TxHex)
	}

}
