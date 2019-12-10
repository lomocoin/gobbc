package gobbc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"unsafe"
)

func TestMakeKeyPair(t *testing.T) {
	tw := &TW{t, true}
	pair, err := MakeKeyPair()
	tw.
		Nil(err).
		True(len(pair.Pubk) == PubkeyHexLen-1, "公钥长度异常", len(pair.Pubk)).
		True(len(pair.Pubk) == len(pair.Privk), "公钥长度应该等于私钥长度？")
	fmt.Printf("pair:%#v\n", pair)
}

func TestGetPubKeyAddress(t *testing.T) {
	tw := TW{t, true}

	tests := []struct {
		name           string
		pubk, shouldBe string
		err            error
	}{
		{
			pubk:     "e8e3770e774d5ad84a8ea65ed08cc7c5c30b42e045623604d5c5c6be95afb4f9",
			shouldBe: "1z6taz5dyrv2xa11pc92y0ggbrf2wf36gbtk8wjprb96qe3kqwfm3ayc1",
		},
		{
			pubk:     "287fd2022a526bfaae2c9780a78a70f4fa7f293b6afb183f1f05e4056b07119b",
			shouldBe: "1kc8getr5wg2hyfrrzdn3pabzzbt712n7g2bjsbqtdd92m0pjfwmfyw9j",
		},
		{
			name:     "自己生成的公钥",
			pubk:     "2b9ff534924ee322a73cd6fccc839f666b559f48c7fc68b16c5a69ba448dc4b0",
			shouldBe: "1p328th5td5d6scb8zk3mh7tnddk9z0yczkb3s9s2wd794d7nkwnk1n2w",
		},
	}

	for _, tt := range tests {
		pubk, shouldBe := tt.pubk, tt.shouldBe
		add, err := GetPubKeyAddress(pubk)
		tw.Nil(err).
			True(shouldBe == add, "地址不对", shouldBe)
	}

}
