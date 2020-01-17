package gobbc

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMakeKeyPair(t *testing.T) {
	tw := &TW{t, true}
	for i := 0; i < 2; i++ {
		pair, err := MakeKeyPair()
		tw.
			Nil(err).
			True(len(pair.Pubk) == PubkeyHexLen-1, "公钥长度异常", len(pair.Pubk)).
			True(len(pair.Pubk) == len(pair.Privk), "公钥长度应该等于私钥长度？")
		fmt.Printf("pair:%#v\n", pair)
	}
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

func TestTemplateAddr(t *testing.T) {
	// TODO 增加测试数据
	// 正常解析
	// 错误的长度
	// 公钥的解析
	// 。。。
	tw := TW{T: t}
	h := "02000102ff1b5b6a4c177953f738ac2eebdcaee40a1131530612cafcd86f509ac7c0b81f01654a017cb2c46cc21452ee2c8d52e70a8570393937264691da9f76be6c6f38a701"
	b, err := hex.DecodeString(h)
	tw.Nil(err)

	fmt.Println("expected:2+2+33*2 = 70", len(b))
	b = b[2:]
	fmt.Println("mn1(32+1)2(32+1) = 68", len(b))
	fmt.Println("m-n", b[:2])
	b = b[2:]
	fmt.Println("前33", b[:33])
	fmt.Println("后33", b[33:])

	for _, pub := range []string{
		"a7386f6cbe769fda91462637393970850ae7528d2cee5214c26cc4b27c014a65",
		"1fb8c0c79a506fd8fcca12065331110ae4aedceb2eac38f75379174c6a5b1bff",
	} {
		k, err := ParsePublicKeyHex(pub)
		tw.Nil(err)
		fmt.Println(k)
	}

}
