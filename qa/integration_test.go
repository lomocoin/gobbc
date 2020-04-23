package qa

import (
	"fmt"
	"math"
	"testing"

	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
)

// 1 测试生成的地址，导入后与钱包获取到的公钥一致
// 2 交易签名可以正常上链
// 3 序列化和解析正常

func TestMakekeypair(t *testing.T) {
	tw := gobbc.TW{T: t}
	const pass = "123"

	killNode, client, minerAddr := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: false, KeepTmpDirInKill: true,
	})
	defer killNode()

	pair, err := gobbc.MakeKeyPair()
	tw.Nil(err)

	t.Run("可以正常导入私钥，根据公钥转换的地址一致", func(_t *testing.T) {
		pubkP, err := client.Importprivkey(pair.Privk, pass)
		tw.Nil(err).Equal(pair.Pubk, *pubkP)

		addr, err := client.Getpubkeyaddress(pair.Pubk, nil)
		tw.Nil(err).Equal(pair.Addr, *addr)
	})

	//测试签名
	prepareAmount := 30.0
	outAmount := 10.0
	{ //准备资金给地址
		tw.Continue(false).Nil(bbrpc.Wait4balanceReach(minerAddr, 100, client))
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			From:   minerAddr,
			To:     pair.Addr,
			Amount: prepareAmount,
		})
		tw.Nil(err)
		tw.Nil(bbrpc.Wait4balanceReach(pair.Addr, prepareAmount, client))
	}

	t.Run("可以正常签名，签名结果与用rpc签名的一致,签名结果可以正常广播", func(_t *testing.T) {
		txdata, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
			From:   pair.Addr,
			To:     minerAddr,
			Amount: outAmount,
		})
		tw.Nil(err).True(txdata != nil)

		tx, err := gobbc.DecodeRawTransaction(*txdata, false)
		tw.Nil(err)
		tx.Version = math.MaxUint16
		// _ = math.MaxUint16
		tw.Nil(tx.SignWithHexedKey(pair.Privk))

		signedTx, err := tx.Encode(true)
		tw.Nil(err)

		_, err = client.Unlockkey(pair.Pubk, pass, nil)
		tw.Nil(err)
		signWithRPC, err := client.Signtransaction(*txdata)
		tw.Nil(err).
			True(signWithRPC.Completed).
			Equal(signedTx, signWithRPC.Hex)

		_, err = client.Sendtransaction(signedTx)
		tw.Nil(err)
	})

	{ //验证余额
		tw.Nil(bbrpc.Wait4nBlocks(1, client))

		bal, err := client.Getbalance(nil, &pair.Addr)
		tw.Nil(err).
			True(len(bal) == 1).
			Continue(true).
			True(bal[0].Avail < prepareAmount-outAmount, "余额不正常")
		fmt.Printf("bal: %#v\n", bal)
	}

}
