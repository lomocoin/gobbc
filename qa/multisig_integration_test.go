package qa

import (
	"fmt"
	"testing"
	"time"

	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
)

func TestMultisigMN(t *testing.T) {
	type mntest struct { //m-n multisig test
		name string
		m, n int
	}
	tw := gobbc.TW{T: t}
	const _pass = "01234"

	tests := []mntest{
		{m: 1, n: 2},
		{m: 2, n: 2},
		{m: 1, n: 3},
		{m: 2, n: 3},
		{m: 3, n: 3},
		{m: 1, n: 4},
	}

	killBigBangServer, client, minerAddress := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: true,
		// NewTmpDir: true,
	})
	defer killBigBangServer()

	tw.Nil(bbrpc.Wait4balanceReach(minerAddress, 100, client))

	for _, mnt := range tests {
		//产生 n + 1 个地址，并且导入这些地址
		// 创建模版地址
		// 验证地址，获取hex
		// 转入资金到模版地址
		// 创建转出交易
		// 随机的m签名，上链，可以正常转出 （这里不使用签名比对的方法，因为不好控制签名的私钥）
		var addrs []gobbc.AddrKeyPair
		var pubks []string

		for i := 0; i < mnt.n+1; i++ {
			add, err := gobbc.MakeKeyPair()
			tw.Nil(err)
			addrs = append(addrs, add)
			_, err = client.Importprivkey(add.Privk, _pass)
			tw.Nil(err)
			_, err = client.Unlockkey(add.Pubk, _pass, nil)
			tw.Nil(err)

			if i < mnt.n {
				pubks = append(pubks, add.Pubk)
			}
		}
		outAddr := addrs[mnt.n].Addr

		tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
			Required: mnt.m,
			Pubkeys:  pubks,
		})
		tw.Nil(err)
		tw.NotZero(tplAddr)
		// fmt.Println("multisig_tpl_addr:", *tplAddr)

		var multisigAddrHex string
		//验证多签地址
		{
			vret, err := client.Validateaddress(*tplAddr)
			tw.Nil(err)
			tw.NotZero(vret)
			// fmt.Printf("tpl_addr: %v\n", gobbc.JSONIndent(*vret))
			multisigAddrHex = vret.Addressdata.Templatedata.Hex
		}

		amount := 99.0
		{ //往多签地址转入资金
			_, err = client.Sendfrom(bbrpc.CmdSendfrom{
				To:     *tplAddr,
				From:   minerAddress,
				Amount: amount,
			})
			tw.Nil(err)
			tw.Nil(bbrpc.Wait4balanceReach(*tplAddr, amount, client))
		}

		fromMultisigAmount := 12.3
		{ //创建交易-签名-广播
			rawtx, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
				From:   *tplAddr,
				To:     outAddr,
				Amount: fromMultisigAmount,
			})
			tw.Nil(err)
			tw.NotZero(rawtx)
			// fmt.Println("created tx hex:", *rawtx)

			var sdkSignResult string
			{ //gobbc 测试
				//decode
				tx, err := gobbc.DecodeRawTransaction(*rawtx, false)
				tw.Nil(err)
				getK := func(s string) []byte {
					b, e := gobbc.ParsePublicKeyHex(s)
					tw.Nil(e)
					return b
				}
				//sign 1
				for i := 0; i < mnt.m; i++ {
					tw.Nil(tx.Multisig(multisigAddrHex, getK(addrs[i].Privk)))
				}

				sdkSignResult, err = tx.Encode(true)
				tw.Nil(err)
				// fmt.Println("gobbc_multisig:", sdkSignResult)
			}

			// sret, err := client.Signtransaction(*rawtx)
			// tw.Nil(err)
			// tw.NotZero(sret)
			// tw.True(sret.Completed)
			// fmt.Println("core_signed_multisig_tx:", sret.Hex)
			// tw.Equal(sret.Hex, sdkSignResult)

			txid, err := client.Sendtransaction(sdkSignResult)
			tw.Nil(err)
			tw.NotZero(txid)

			tw.Nil(bbrpc.Wait4nBlocks(1, client))

			bal, err := client.Getbalance(nil, &outAddr)
			tw.Nil(err)
			tw.Equal(fromMultisigAmount, bal[0].Avail, "1个块后余额不对")
		}
	}
}

// 测试单个节点2个地址的多重签名
func TestMultisigSingleNode(t *testing.T) {
	tw := gobbc.TW{T: t}
	killBigBangServer, client, minerAddress := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: true,
		// NewTmpDir: true,
	})
	defer killBigBangServer()

	tw.Nil(bbrpc.Wait4balanceReach(minerAddress, 100, client))

	// 使用2个地址，产生一个多签地址
	// 将资金转入多签地址
	// 从多签地址将资金转出
	addrs := make([]bbrpc.AddrKeypair, 3)
	for i := 0; i < len(addrs); i++ {
		p, err := client.Makekeypair()
		tw.Nil(err)
		addrs[i] = bbrpc.AddrKeypair{}
		addrs[i].Privkey = p.Privkey
		addrs[i].Pubkey = p.Pubkey
		addrs[i].Address, err = gobbc.GetPubKeyAddress(p.Pubkey)
		tw.Nil(err)
	}
	// addrs := []bbrpc.AddrKeypair{tAddr0, tAddr1, tAddr2}

	a0, a1, a2 := addrs[0], addrs[1], addrs[2]

	{ //导入私钥
		// time.Sleep(time.Second*2)//稍微等待1s
		for _, a := range []bbrpc.AddrKeypair{
			// a0, a1, a2,
			a0, a2, //只导入a0,那么签名也只使用a0的私钥
		} {
			_, err := client.Importprivkey(a.Privkey, _tPassphrase)
			tw.Nil(err)
			_, err = client.Unlockkey(a.Pubkey, _tPassphrase, nil)
			tw.Nil(err)
		}
	}

	tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
		Required: 1,
		// Required: 2,
		Pubkeys: []string{a0.Pubkey, a1.Pubkey},
	})
	tw.Nil(err)
	tw.NotZero(tplAddr)
	// fmt.Println("multisig tpl addr:", *tplAddr)

	var multisigAddrHex string
	//验证多签地址
	{
		vret, err := client.Validateaddress(*tplAddr)
		tw.Nil(err)
		tw.NotZero(vret)
		// fmt.Printf("tpl addr: %v\n", gobbc.JSONIndent(*vret))
		multisigAddrHex = vret.Addressdata.Templatedata.Hex
	}

	amount := 99.0
	{ //往多签地址转入资金
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			To:     *tplAddr,
			From:   minerAddress,
			Amount: amount,
		})
		tw.Nil(err)
		tw.Nil(bbrpc.Wait4balanceReach(*tplAddr, amount, client))
	}

	fromMultisigAmount := 12.3
	{ //创建交易-签名-广播
		rawtx, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
			From:   *tplAddr,
			To:     a2.Address,
			Amount: fromMultisigAmount,
		})
		tw.Nil(err)
		tw.NotZero(rawtx)
		// fmt.Println("created tx hex:", *rawtx)

		_, err = client.Decodetransaction(*rawtx)
		// tw.Nil(err)
		if err == nil {
			// fmt.Printf("decode created tx: %v\n", gobbc.JSONIndent(*deTX))
		}

		var sdkSignResult string
		{ //gobbc 测试
			//decode
			tx, err := gobbc.DecodeRawTransaction(*rawtx, false)
			tw.Nil(err)
			// fmt.Println("gobbc decode tx:", gobbc.JSONIndent(tx))
			hb, err := tx.Encode(false)
			// fmt.Println("tx encode tx:", hb)
			tw.Nil(err).
				Equal(*rawtx, hb)
			getK := func(s string) []byte {
				b, e := gobbc.ParsePublicKeyHex(s)
				tw.Nil(e)
				return b
			}
			//sign 1
			// tw.Nil(tx.Multisig(multisigAddrHex, getK(a1.Privkey)))
			tw.Nil(tx.Multisig(multisigAddrHex, getK(a0.Privkey)))

			sdkSignResult, err = tx.Encode(true)
			tw.Nil(err)
			// fmt.Println("gobbc multisig:", sdkSignResult)
		}

		sret, err := client.Signtransaction(*rawtx)
		tw.Nil(err)
		tw.NotZero(sret)
		tw.True(sret.Completed)

		// fmt.Println("signed_multisig_tx:", sret.Hex)
		{ //gobbc 测试
			tx, err := gobbc.DecodeRawTransaction(sret.Hex, true)
			tw.Nil(err)
			// fmt.Println("gobbc decode tx:", gobbc.JSONIndent(tx))
			hb, err := tx.Encode(true)
			// fmt.Println("tx encode tx:", hb)
			tw.Nil(err).
				Equal(sret.Hex, hb)

			fmt.Printf("%#v\n", addrs)
			tw.Continue(false).Equal(sdkSignResult, sret.Hex, "sdk签名应该与core签名一致")
		}

		// fmt.Printf("compare_sign:\n%s\n%s\n%v\n", sdkSignResult, sret.Hex, sdkSignResult == sret.Hex)

		// txid, err := client.Sendtransaction(sret.Hex)
		txid, err := client.Sendtransaction(sdkSignResult)
		tw.Nil(err)
		tw.NotZero(txid)
		time.Sleep(time.Second)

		tw.Nil(bbrpc.Wait4balanceReach(a2.Address, fromMultisigAmount, client))
	}

}

// 测试单个节点2个地址的多重签名,只将模版导入钱包，不导入私钥
func TestMultisigOnlyTemplate(t *testing.T) {
	tw := gobbc.TW{T: t}
	killBigBangServer, client, minerAddress := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: true,
		// NewTmpDir: true,
	})
	defer killBigBangServer()

	tw.Nil(bbrpc.Wait4balanceReach(minerAddress, 100, client))

	// 使用2个地址，产生一个多签地址
	// 将资金转入多签地址
	// 从多签地址将资金转出
	addrs := make([]bbrpc.AddrKeypair, 3)
	for i := 0; i < len(addrs); i++ {
		p, err := client.Makekeypair()
		tw.Nil(err)
		addrs[i] = bbrpc.AddrKeypair{}
		addrs[i].Privkey = p.Privkey
		addrs[i].Pubkey = p.Pubkey
		addrs[i].Address, err = gobbc.GetPubKeyAddress(p.Pubkey)
		tw.Nil(err)
	}
	// addrs := []bbrpc.AddrKeypair{tAddr0, tAddr1, tAddr2}

	a0, a1, a2 := addrs[0], addrs[1], addrs[2]

	{ //导入私钥
		_, err := client.Importprivkey(a2.Privkey, _tPassphrase)
		tw.Nil(err)

		_, err = client.Unlockkey(a2.Pubkey, _tPassphrase, nil)
		tw.Nil(err)
	}

	tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
		Required: 2,
		Pubkeys:  []string{a0.Pubkey, a1.Pubkey},
	})
	tw.Nil(err)
	tw.NotZero(tplAddr)
	// fmt.Println("multisig tpl addr:", *tplAddr)

	var multisigAddrHex string
	//验证多签地址
	{
		vret, err := client.Validateaddress(*tplAddr)
		tw.Nil(err)
		tw.NotZero(vret)
		// fmt.Printf("tpl addr: %v\n", gobbc.JSONIndent(*vret))
		multisigAddrHex = vret.Addressdata.Templatedata.Hex
	}

	amount := 99.0
	{ //往多签地址转入资金
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			To:     *tplAddr,
			From:   minerAddress,
			Amount: amount,
		})
		tw.Nil(err)
		tw.Nil(bbrpc.Wait4balanceReach(*tplAddr, amount, client))
	}

	fromMultisigAmount := 12.3
	{ //创建交易-签名-广播
		rawtx, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
			From:   *tplAddr,
			To:     a2.Address,
			Amount: fromMultisigAmount,
		})
		tw.Nil(err)
		tw.NotZero(rawtx)
		// fmt.Println("created tx hex:", *rawtx)

		var sdkSignResult string
		{ //gobbc 测试
			//decode
			tx, err := gobbc.DecodeRawTransaction(*rawtx, false)
			tw.Nil(err)
			hb, err := tx.Encode(false)
			// fmt.Println("tx encode tx:", hb)
			tw.Nil(err).
				Equal(*rawtx, hb)
			getK := func(s string) []byte {
				b, e := gobbc.ParsePublicKeyHex(s)
				tw.Nil(e)
				return b
			}
			//sign 1
			tw.Nil(tx.Multisig(multisigAddrHex, getK(a1.Privkey)))
			tw.Nil(tx.Multisig(multisigAddrHex, getK(a0.Privkey)))

			sdkSignResult, err = tx.Encode(true)
			tw.Nil(err)
			// fmt.Println("gobbc multisig:", sdkSignResult)
		}

		// txid, err := client.Sendtransaction(sret.Hex)
		txid, err := client.Sendtransaction(sdkSignResult)
		tw.Nil(err)
		tw.NotZero(txid)
		time.Sleep(time.Second)

		tw.Nil(bbrpc.Wait4nBlocks(1, client))
		bal, err := client.Getbalance(nil, &a2.Address)
		tw.Nil(err).
			Equal(fromMultisigAmount, bal[0].Avail, "1个块后余额不对")
	}

}
