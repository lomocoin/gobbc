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
		skip bool
	}
	tw := gobbc.TW{T: t}
	const _pass = "01234"

	tests := []mntest{
		{m: 1, n: 2, skip: false},
		{m: 2, n: 2, skip: false},
		{m: 1, n: 3, skip: false},
		{m: 2, n: 3, skip: false},
		{m: 3, n: 3, skip: false},
		{m: 1, n: 4, skip: false},
	}

	killBigBangServer, client, minerAddress := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: true,
	})
	defer killBigBangServer()

	tw.Nil(bbrpc.Wait4balanceReach(minerAddress, 100, client))

	for idx, mnt := range tests {
		if mnt.skip {
			continue
		}
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
			if i < mnt.n {
				pubks = append(pubks, add.Pubk)
			}
			if i == mnt.n {
				client.Importpubkey(add.Pubk)
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
					beforeSdkSign, err := tx.Encode(true)
					tw.Nil(err)

					tw.Nil(tx.Multisig(multisigAddrHex, getK(addrs[i].Privk)))

					_, err = client.Importprivkey(addrs[i].Privk, _pass)
					tw.Nil(err)
					_, err = client.Unlockkey(addrs[i].Pubk, _pass, nil)
					tw.Nil(err)

					sret, err := client.Signtransaction(beforeSdkSign)
					tw.Nil(err)
					tw.NotZero(sret)
					// fmt.Println("core_signed_multisig_tx:", sret.Hex)

					sdkSignResult, err = tx.Encode(true)
					tw.Nil(err)

					tw.Equal(sret.Hex, sdkSignResult, "sdk签名应该与core签名一致", *rawtx, multisigAddrHex)
				}

				// fmt.Println("gobbc_multisig:", sdkSignResult)
			}

			txid, err := client.Sendtransaction(sdkSignResult)
			tw.Nil(err, "idx:", idx)
			tw.NotZero(txid)

			tw.Nil(bbrpc.Wait4nBlocks(1, client))

			bal, err := client.Getbalance(nil, &outAddr)
			tw.Nil(err)
			tw.Equal(fromMultisigAmount, bal[0].Avail, "1个块后余额不对")
		}
		fmt.Println("TEST >> ", mnt)
	}
}

// 开发用,x-2签名,节点导入第0个私钥
func Test_DevMultisig_1of2(t *testing.T) {
	tw := gobbc.TW{T: t}
	killBigBangServer, client, minerAddress := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: true,
	})
	defer killBigBangServer()

	tw.Nil(bbrpc.Wait4balanceReach(minerAddress, 100, client))

	// 使用2个地址，产生一个多签地址
	// 将资金转入多签地址
	// 从多签地址将资金转出
	addrs := []gobbc.AddrKeyPair{
		{Privk: "9d05976ea6cd5d8c4d6fc7f18fce38ae32c43cc668556682fa16d90b99c8c183",
			Pubk: "c88c7653f0fdd945ff3545f78cb6b27e34763bce324aa3edbdaa48d2ec2da3cc",
			Addr: "1sjhjvv6j92nbvvd398scwevp6hzb5dmcyx2kbzt5v7yz0mvphk4dqxr6"},
		{Privk: "b1b73e997c023f4474fd5ed793686addc4f51d3b1a89e27b317e83060f5b716d",
			Pubk: "cc1246af9430728982631366b886787f324e07d395a5b3ebd38d2c74f82cc243",
			Addr: "18f12sy3m5j6x7txkmpax61te69zqh1nrcr9p70m9e8r99bt62b601vrp"},
	}
	a0, a1 := addrs[0], addrs[1]

	multisigAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
		// Required: 1,
		Required: 2,
		Pubkeys:  []string{a0.Pubk, a1.Pubk},
	})
	tw.Nil(err)
	tw.NotZero(multisigAddr)
	// fmt.Println("multisig tpl addr:", *multisigAddr)

	var multisigAddrHex string
	//验证多签地址
	{
		vret, err := client.Validateaddress(*multisigAddr)
		tw.Nil(err)
		tw.NotZero(vret)
		// fmt.Printf("tpl addr: %v\n", gobbc.JSONIndent(*vret))
		multisigAddrHex = vret.Addressdata.Templatedata.Hex
		// fmt.Println("tpl hex:", multisigAddrHex)
	}

	amount := 99.0
	{ //往多签地址转入资金
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			To:     *multisigAddr,
			From:   minerAddress,
			Amount: amount,
		})
		tw.Nil(err)
		tw.Nil(bbrpc.Wait4balanceReach(*multisigAddr, amount, client))
	}

	fromMultisigAmount := 12.3
	toAddr := a0.Addr
	{ //创建交易-签名-广播
		rawtx, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
			From:   *multisigAddr,
			To:     toAddr,
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

		sdkSignResult := *rawtx
		for i, a := range []gobbc.AddrKeyPair{
			a1, a0,
			// a0, a1,
		} {
			_, err := client.Importprivkey(a.Privk, _tPassphrase)
			tw.Nil(err)
			_, err = client.Unlockkey(a.Pubk, _tPassphrase, nil)
			tw.Nil(err)

			coreSigned, err := client.Signtransaction(sdkSignResult)
			tw.Nil(err)
			tw.NotZero(coreSigned)
			if i == 1 {
				tw.True(coreSigned.Completed)
			}

			{ //gobbc 测试
				//decode
				tx, err := gobbc.DecodeRawTransaction(sdkSignResult, true)
				tw.Nil(err)
				// fmt.Println("gobbc decode tx:", gobbc.JSONIndent(tx))
				// hb, err := tx.Encode(false)
				// fmt.Println("tx encode tx:", hb)
				// tw.Nil(err).Equal(sdkSignResult, hb, "应该正确编码tx")
				getK := func(s string) []byte {
					b, e := gobbc.ParsePublicKeyHex(s)
					tw.Nil(e)
					return b
				}
				tw.Nil(tx.Multisig(multisigAddrHex, getK(a.Privk)))

				sdkSignResult, err = tx.Encode(true)
				tw.Nil(err)
				// fmt.Println("gobbc multisig:", sdkSignResult)
				tw.Continue(false).Equal(coreSigned.Hex, sdkSignResult, "sdk签名应该与core签名一致", i, *rawtx)
			}
			// fmt.Printf("core sign and sdk sign:\n%s\n%s\n", coreSigned.Hex, sdkSignResult)

			{ //gobbc 测试
				// tx, err := gobbc.DecodeRawTransaction(coreSigned.Hex, true)
				// tw.Nil(err)
				// fmt.Println("gobbc decode tx:", gobbc.JSONIndent(tx))
				// encodeTX, err := tx.Encode(true)
				// fmt.Println("tx encode tx:", encodeTX)
				// tw.Nil(err).Equal(coreSigned.Hex, encodeTX)
			}
		}

		// fmt.Printf("compare_sign:\n%s\n%s\n%v\n", sdkSignResult, sret.Hex, sdkSignResult == sret.Hex)

		// txid, err := client.Sendtransaction(sret.Hex)
		txid, err := client.Sendtransaction(sdkSignResult)
		tw.Nil(err)
		tw.NotZero(txid)

		tw.Nil(bbrpc.Wait4balanceReach(toAddr, fromMultisigAmount, client))
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
		for _, a := range []bbrpc.AddrKeypair{
			a2,
			// a0, a1, a2,
		} {
			_, err := client.Importprivkey(a.Privkey, _tPassphrase)
			tw.Nil(err)
			_, err = client.Unlockkey(a.Pubkey, _tPassphrase, nil)
			tw.Nil(err)
		}
	}

	multisigAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
		// Required: 1,
		Required: 2,
		Pubkeys:  []string{a0.Pubkey, a1.Pubkey},
	})
	tw.Nil(err)
	tw.NotZero(multisigAddr)
	// fmt.Println("multisig tpl addr:", *multisigAddr)

	var multisigAddrHex string
	//验证多签地址
	{
		vret, err := client.Validateaddress(*multisigAddr)
		tw.Nil(err)
		tw.NotZero(vret)
		// fmt.Printf("tpl addr: %v\n", gobbc.JSONIndent(*vret))
		multisigAddrHex = vret.Addressdata.Templatedata.Hex
	}

	amount := 99.0
	{ //往多签地址转入资金
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			To:     *multisigAddr,
			From:   minerAddress,
			Amount: amount,
		})
		tw.Nil(err)
		tw.Nil(bbrpc.Wait4balanceReach(*multisigAddr, amount, client))
	}

	fromMultisigAmount := 12.3
	{ //创建交易-签名-广播
		rawtx, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
			From:   *multisigAddr,
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
