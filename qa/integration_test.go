package qa

import (
	"fmt"
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
		NewTmpDir: true, NotPrint2stdout: true,
	})
	defer killNode()

	pair, err := gobbc.MakeKeyPair()
	tw.Nil(err)

	{ //验证生成的私钥与对应的公钥、地址正确
		pubkP, err := client.Importprivkey(pair.Privk, pass)
		tw.Nil(err).Equal(pair.Pubk, *pubkP)

		addr, err := client.Getpubkeyaddress(pair.Pubk, nil)
		tw.Nil(err).Equal(pair.Addr, *addr)
	}

	{ //测试签名
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

		{ //创建交易，然后离线签名、广播
			txdata, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
				From:   pair.Addr,
				To:     minerAddr,
				Amount: outAmount,
			})
			tw.Nil(err).True(txdata != nil)

			tx, err := gobbc.DecodeRawTransaction(*txdata, false)
			tw.Nil(err)
			tw.Nil(tx.SignWithHexedKey(pair.Privk))

			signedTx, err := tx.Encode(true)
			tw.Nil(err)

			_, err = client.Sendtransaction(signedTx)
			tw.Nil(err)
		}

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

}
