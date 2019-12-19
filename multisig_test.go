package gobbc

import (
	"fmt"
	"golang.org/x/crypto/blake2b"
	"testing"
)

type key struct {
	privk, pubk []byte
}

//该测试为一个"bug"/特性展示，作为代码参考，非代码测试用例
func TestEd25519_scalarMarshal(t *testing.T) {
	tw := TW{T: t}

	//对于下面的2组scalar,表现值一致，但mulBase之后值不同
	for _, scBytes := range [][]byte{
		{187, 54, 105, 185, 138, 165, 51, 76, 20, 152, 17, 219, 12, 149, 225, 165, 223, 179, 171, 111, 206, 240, 140, 43, 124, 150, 86, 223, 143, 17, 99, 164},
		{121, 239, 206, 23, 131, 198, 123, 219, 180, 119, 101, 125, 90, 210, 43, 213, 222, 179, 171, 111, 206, 240, 140, 43, 124, 150, 86, 223, 143, 17, 99, 4},
	} {
		sc := cv25.Scalar()
		err := sc.UnmarshalBinary(scBytes)
		tw.Nil(err)

		fmt.Println(sc)
		fmt.Println(sc.MarshalBinary())

		riPoint := cv25.Point().Base().Mul(sc, nil)
		fmt.Println(riPoint.MarshalBinary())
	}
}

func TestMultidebug(t *testing.T) {
	t.Skip("调试用测试用例，不作为测试执行")

	tw := TW{T: t}
	var err error

	keys := []key{
		{
			privk: []byte{185, 4, 33, 53, 9, 7, 154, 207, 159, 111, 37, 31, 132, 247, 214, 64, 57, 20, 56, 44, 96, 106, 146, 204, 110, 161, 161, 161, 176, 100, 56, 136},  //sec0
			pubk:  []byte{2, 122, 196, 9, 54, 173, 240, 245, 224, 253, 37, 145, 13, 43, 92, 18, 227, 115, 11, 178, 170, 197, 96, 245, 238, 171, 38, 227, 117, 139, 48, 3}, //pub0
		},
		{
			privk: []byte{226, 158, 54, 228, 14, 67, 197, 67, 158, 229, 16, 168, 173, 5, 195, 245, 196, 12, 86, 147, 255, 79, 116, 239, 119, 217, 59, 82, 89, 224, 40, 42},      //sec1
			pubk:  []byte{254, 168, 46, 138, 143, 1, 18, 210, 248, 201, 157, 133, 189, 64, 74, 153, 248, 235, 8, 179, 12, 47, 196, 250, 161, 148, 230, 102, 147, 242, 119, 177}, //pub1
		},
		{
			privk: []byte{227, 232, 198, 98, 160, 165, 35, 166, 221, 196, 215, 143, 194, 75, 3, 88, 236, 53, 69, 132, 203, 230, 58, 109, 244, 74, 73, 183, 2, 79, 53, 88},   //sec2
			pubk:  []byte{133, 165, 31, 231, 178, 101, 110, 244, 240, 22, 20, 103, 11, 80, 51, 48, 121, 222, 44, 43, 173, 227, 43, 24, 203, 79, 142, 126, 207, 38, 80, 113}, //pub2
		},
	}

	nKeys := 3
	nPart := 3

	anchorBytes := []byte{60, 181, 171, 152, 229, 245, 226, 165, 13, 111, 203, 177, 183, 221, 194, 108, 217, 181, 39, 91, 121, 181, 249, 156, 129, 217, 116, 113, 176, 42, 227, 168}
	msgBytes := []byte{170, 180, 100, 146, 8, 197, 214, 27, 116, 254, 107, 193, 246, 68, 111, 12, 226, 18, 17, 252, 237, 55, 52, 189, 34, 158, 18, 81, 221, 222, 229, 52}

	var pubks, privks [][]byte
	for i, k := range keys {
		if i >= nKeys {
			break
		}
		pubks = append(pubks, k.pubk)
		privks = append(privks, k.privk)
	}
	// pubks := [][]byte{keys[0].pubk, keys[1].pubk, keys[2].pubk}
	// privks := [][]byte{keys[0].privk, keys[1].privk, keys[2].privk}
	// privks := [][]byte{keys[0].privk, keys[1].privk}
	// privks := [][]byte{keys[0].privk}
	var sig []byte
	for i := 0; i < nPart; i++ {
		privk := privks[i]
		sig, err = CryptoMultiSign(pubks, privk, anchorBytes, msgBytes, sig)
		tw.Nil(err)
		fmt.Println("si", i, sig)
	}
}

func TestTxidCal(t *testing.T) {
	// TODO 补充测试数据
	// 从生产环境获取的
	// 覆盖率要求

	tw := TW{T: t}
	data := "010000000dedfa5d00000000d4a8f445791e35471b69254e444a4eac2e2448f57b420a6535f935c3000000000153acd59d5c42024c66c62f4fb7e176776046e2237425048fe92979ea0dedfa5d00018aa81abeebdb87a64040aa9c3a229725383cfc2af49d6573cb9c62b74a531059e0aebb000000000064000000000000000000"
	tx, err := DecodeRawTransaction(data, false)
	tw.Nil(err)

	b, err := tx.EncodeBytes(false)
	tw.Nil(err)

	b = b[:len(b)-1]
	fmt.Println(b)
	fmt.Println(blake2b.Sum256(b)) //=== RUN   TestTxidCal
	// [207 225 2 244 19 144 49 82 77 173 113 180 238 70 103 253 20 237 190 22 73 206 11 128 235 123 239 224 176 98 39 58]
}
