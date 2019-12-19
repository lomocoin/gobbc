package gobbc

import (
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestDecodeRawTransaction(t *testing.T) {
	raw := "010000004aeaed5d00000000701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b00000000002799a49bcd8ca8723aa00aad86cec19d4d095191c20ce44000cfa7f6b09e9ed5d002b8336b3f242db6ecdc939c168f9613b14f0f4fd00418c3c9ba849c14aeaed5d0101f30b1fd894ba3eacf1b2309ce9fcb606892a70604af5791a732df423e47f001d9c64cd1d000000006400000000000000008164f1a77bd0e00f8023ffa2f7e0a76eb795414d9a57eb2f4ce5e9cc730c8103c501e1cbd24fa95312b81d2dc5ef6f60c39a9485819d4fa11bcfdde5f99151c8a4f981e14068ae196ce63ef403bc335ff439a00d1f00cc3e45cfc057354ea408cafad8e1fb769de3672a155545d490813e1c6eeefb7b4dec678e669c5de7e3c20b07"
	_ = `
	{
		"transaction" : {
			"txid" : "5dedea4ac48d33229b61a4b7d7f5e8e84833775250cb8fa7091564943b7f8e1f",
			"version" : 1,
			"type" : "token",
			"time" : 1575873098,
			"lockuntil" : 0,
			"anchor" : "00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70",
			"vin" : [
				{
					"txid" : "5dede9096b7ffa0c0044ce201c1995d0d419ec6cd8aa00aa2387cad8bc499a79",
					"vout" : 0
				},
				{
					"txid" : "5dedea4ac149a89b3c8c4100fdf4f0143b61f968c139c9cd6edb42f2b336832b",
					"vout" : 1
				}
			],
			"sendto" : "1yc5hzp4mq8zaswdj62eekz5p0t4jmw309btqj6kk5qt27s3z00embbrg",
			"amount" : 499.999900,
			"txfee" : 0.000100,
			"data" : "",
			"sig" : "64f1a77bd0e00f8023ffa2f7e0a76eb795414d9a57eb2f4ce5e9cc730c8103c501e1cbd24fa95312b81d2dc5ef6f60c39a9485819d4fa11bcfdde5f99151c8a4f981e14068ae196ce63ef403bc335ff439a00d1f00cc3e45cfc057354ea408cafad8e1fb769de3672a155545d490813e1c6eeefb7b4dec678e669c5de7e3c20b07",
			"fork" : "00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70",
			"confirmations" : 19
		}
	}
	`
	tw := TW{t, true}

	tx, err := DecodeRawTransaction(raw, true)
	tw.Nil(err)

	tw.Equal(uint16(1), tx.Version, "bad version").
		IsZero(tx.Typ, "bad type").
		Equal(uint32(1575873098), tx.Timestamp, "bad timestamp").
		IsZero(tx.LockUntil, "bad lock until").
		Equal("00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70", tx.HashAnchor, "bad anchor").
		Equal("1yc5hzp4mq8zaswdj62eekz5p0t4jmw309btqj6kk5qt27s3z00embbrg", tx.Address, "bad address").
		Equal(uint8(2), tx.SizeIn).
		Equal(int64(499_999_900), tx.Amount, "bad amount").
		Equal(int64(100), tx.TxFee, "bad tx fee")

	fmt.Println("tx: ", JSONIndent(tx))
}

func TestTransactionDecodeEncode(t *testing.T) {
	tw := TW{T: t}
	{
		createdTxHexData := "010000004411d55d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc0000000001e9f3b5c8fe00417e1c06cd099af2417813b0163c5a701cc9bb4da8504710d55d00011915eb90d9f9d0d92233e33793d04c0a5f6384e65fdc2ea0ff098c5db28d910540420f000000000064000000000000000000"

		txWithoutSign, err := DecodeRawTransaction(createdTxHexData, false)

		tw.Continue(false).
			Nil(err).
			Continue(true).
			Equal(uint16(1), txWithoutSign.Version, "bad version").
			IsZero(txWithoutSign.Typ, "bad type").
			Equal(uint32(1574244676), txWithoutSign.Timestamp, "bad timestamp").
			IsZero(txWithoutSign.LockUntil, "bad lock until").
			Equal("00000000dcde418dca150e49f53ab857d5ccd095a800bfb29ea87385267bc069", txWithoutSign.HashAnchor, "bad anchor").
			Equal("134ayq46sz78dj8hkwcvs7m2c19fp7176bze2x87z1665vcmdj42y7a7s", txWithoutSign.Address, "bad address").
			Equal(uint8(1), txWithoutSign.SizeIn).
			Equal(uint8(0), txWithoutSign.SizeOut).
			Equal(int64(1000_000), txWithoutSign.Amount, "bad amount").
			Equal(int64(100), txWithoutSign.TxFee, "bad tx fee")

		serializedHexWithoutSign, err := txWithoutSign.Encode(false)

		tw.Continue(false).
			Nil(err).
			Continue(true).
			Equal(createdTxHexData, serializedHexWithoutSign, "序列化错误")
	}

	{
		signedTxHexData := "010000008d31d65d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc000000000191b5093377f21fc5a76435351504ce5eae7591380cc3502672fb23c2f230d65d00016f757a33cf3b4f83f2b37b2308090f949c6f3870d50ceb3e5aa59b3118c66d7240420f0000000000640000000000000000816f757a33cf3b4f83f2b37b2308090f949c6f3870d50ceb3e5aa59b3118c66d720100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14fa178a313c5800bebda19cff9e745a346725838c9b5ecb388797bc04a21bca4a9077dc2140b805b6816ab2a35e692821b7904dcd8bbd52f14c7e5c095b1f20308"
		tx, err := DecodeRawTransaction(signedTxHexData, true)
		tw.Continue(false).Nil(err)

		serializedHex, err := tx.Encode(true)
		tw.Nil(err).
			Continue(true).
			Equal(signedTxHexData, serializedHex, "encode with sign data failed")
	}

	{ //测试签名
		createdTxHexData1 := "010000005948d75d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc0000000002e563f10b18dc361305815da5b464ae6af0a39e5ef2dccf1a74e63b219781d65d00a43970696b5c1b39b0bf4bc0b68df5fb993213c367709a0b3cd9b42c8d31d65d000100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14f40420f000000000064000000000000000000"
		privkHex := "3a7a45f05643fa2e7eeb11da2e2c66e43ddf4f7535dccbb3e6c07fb39201b1df"
		signedTxHexData1 := "010000005948d75d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc0000000002e563f10b18dc361305815da5b464ae6af0a39e5ef2dccf1a74e63b219781d65d00a43970696b5c1b39b0bf4bc0b68df5fb993213c367709a0b3cd9b42c8d31d65d000100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14f40420f0000000000640000000000000000400d6c650009275f9fa4f64cbd4712e995f84f00f96d056b4610d983c8d0cbad8aefcf75dbfa3f9afaf4bd27e9062f96a2fbc8a98a4feb796bfde547dcb9836b0c"
		tx, err := DecodeRawTransaction(createdTxHexData1, false)
		tw.Continue(false).Nil(err)

		err = tx.SignWithHexedKey(privkHex)
		tw.Continue(false).Nil(err)

		data, err := tx.Encode(true)

		tw.Continue(false).Nil(err).
			Continue(true).Equal(signedTxHexData1, data)
	}

}

func TestTxid(t *testing.T) {
	tw := TW{T: t}
	txData := "01000000f11de55d00000000701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b000000000014919fa098ca5acd9e990349c605f679b370d587086fa6428339415eff11de55d01017c755b96a15a57a7253d2bf80a1d9c4ca84a9a70da6ab77ab96661fc7b7193cf1027000000000000640000000000000000400cb19f280e587741bb1bd9c5803e7867e1995419fa2acc35a8f669cf70596276ccc7a2397940796d6356f5ad7d41778dbca06db1132546167e9f9d23cdb5f806"
	tx, err := DecodeRawTransaction(txData, false)
	tw.Nil(err)

	b, err := tx.EncodeBytes(false)
	tw.Nil(err)

	b = b[:len(b)-4]

	sum := blake2b.Sum256(b)
	fmt.Println(hex.EncodeToString(sum[:]))
	//5de51df120c2762e6590be7c3bf259d61c50995202ff6e3c646144705538ea30
	//667d30119521ad92f6f6626f8e397219ad393270ed2bfbc542998ba7bb415dad
}
