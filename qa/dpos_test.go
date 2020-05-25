package qa

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
)

func init() {
	log.SetPrefix("dbg-log")
}

// 该测试演示使用RPC进行下述操作
// 创建代理, 给自己投票, 创建投票地址, 给他人投票, 赎回投票
func TestPosRpc(t *testing.T) {
	if testing.Short() {
		t.Skip("skip short")
	}

	tw := gobbc.TW{T: t}
	const pass = "123"

	killNode, client, minerAddr := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: false, KeepTmpDirInKill: true,
	})
	// bigbang-cli -rpcuser=rpcusr -rpcpassword=pwd -rpcport=19906
	defer killNode()

	delegateAddr, dposMine2Addr, voteAddr := tAddr0, tAddr1, tAddr2
	_ = voteAddr
	tw.Nil(bbrpc.Wait4balanceReach(minerAddr, 100, client, "矿工挖到基础资本"))
	for _, x := range []bbrpc.AddrKeypair{
		tAddr0, tAddr1, tAddr2,
	} {
		_, err := client.Importprivkey(x.Privkey, pass)
		tw.Nil(err)
		_, _ = client.Unlockkey(x.Pubkey, pass, nil)
	}

	var delegateTemplateAddress string
	t.Run("创建DPOS delegate模版", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamDelegate{
			Delegate: delegateAddr.Pubkey,
			Owner:    dposMine2Addr.Address,
		})
		w.Nil(err)
		delegateTemplateAddress = *tplAddr
		log.Println("delegate tpl addr:", delegateTemplateAddress)
	})

	registeredAssets := 233.3
	amount := 10.0
	amount++
	t.Run("delegator 投票给自己", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		{ //首先给该地址准备资金
			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   minerAddr,
				To:     dposMine2Addr.Address,
				Amount: registeredAssets,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(dposMine2Addr.Address, registeredAssets, client, "给delegator准备原始资产"))
		}
		_, err := client.Sendfrom(bbrpc.CmdSendfrom{
			From:   dposMine2Addr.Address,
			To:     delegateTemplateAddress,
			Amount: amount,
		})
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(delegateTemplateAddress, amount, client, "验证给自己投票成功"))
	})

	var voteTemplateAddr string
	amount++
	t.Run("创建投票地址", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		addr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamVote{
			Delegate: delegateTemplateAddress,
			Owner:    voteAddr.Address,
		})
		w.Nil(err)
		voteTemplateAddr = *addr
		log.Println("vote template addr:", voteTemplateAddr)
	})

	t.Run("给他人投票", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		{ //首先给投票用户准备点资产
			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   minerAddr,
				To:     voteAddr.Address,
				Amount: registeredAssets,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(voteAddr.Address, registeredAssets, client, "给voter准备原始资产"))
		}

		_, err := client.Sendfrom(bbrpc.CmdSendfrom{
			From:   voteAddr.Address,
			To:     voteTemplateAddr,
			Amount: amount,
		})
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(voteTemplateAddr, amount, client, "验证voter投票成功"))
	})

	voterBalance := registeredAssets - amount
	amount--
	t.Run("赎回投票", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		_, err := client.Sendfrom(bbrpc.CmdSendfrom{
			From:   voteTemplateAddr,
			To:     voteAddr.Address,
			Amount: amount,
		})
		// _, err := signAndSendtransaction(bbrpc.CmdSendfrom{
		// 	From:   voteTemplateAddr,
		// 	To:     voteAddr.Address,
		// 	Amount: amount,
		// }, voteAddr.Privkey, client)

		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(voteAddr.Address, voterBalance+amount-0.01, client, "验证voter赎回成功"))
	})
	log.Println("done")
	time.Sleep(5 * time.Second)
}

// 测试使用gobbc sdk进行下述操作
// 创建代理
// 给自己投票
// 创建投票地址
// 给他人投票
// 赎回投票
func TestPosSDK(t *testing.T) {
	if testing.Short() {
		t.Skip("skip short")
	}

	tw := gobbc.TW{T: t}
	const pass = "123"

	killNode, client, minerAddr := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: false, KeepTmpDirInKill: true,
	})
	// bigbang-cli -rpcuser=rpcusr -rpcpassword=pwd -rpcport=19906
	defer killNode()

	delegateAddr, dposMine2Addr, voteAddr := tAddr0, tAddr1, tAddr2
	_ = voteAddr
	tw.Nil(bbrpc.Wait4balanceReach(minerAddr, 600, client, "矿工挖到基础资本"))
	for _, x := range []bbrpc.AddrKeypair{
		tAddr0, tAddr1, tAddr2,
	} {
		_, err := client.Importprivkey(x.Privkey, pass)
		tw.Nil(err)
		_, _ = client.Unlockkey(x.Pubkey, pass, nil)
	}

	var delegateTemplateAddress string
	t.Run("创建DPOS delegate模版", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamDelegate{
			Delegate: delegateAddr.Pubkey,
			Owner:    dposMine2Addr.Address,
		})
		w.Nil(err)
		delegateTemplateAddress = *tplAddr
		log.Println("delegate tpl addr:", delegateTemplateAddress)
	})

	registeredAssets := 233.3
	amount := 10.0
	amount++
	t.Run("delegator 投票给自己", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		{ //首先给该地址准备资金
			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   minerAddr,
				To:     dposMine2Addr.Address,
				Amount: registeredAssets,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(dposMine2Addr.Address, registeredAssets, client, "给delegator准备原始资产"))
		}
		_, err := signAndSendtransaction(bbrpc.CmdSendfrom{
			From:   dposMine2Addr.Address,
			To:     delegateTemplateAddress,
			Amount: amount,
		}, []string{dposMine2Addr.Privkey}, client)
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(delegateTemplateAddress, amount, client, "验证给自己投票成功"))
	})

	var voteTemplateAddr string
	amount++
	t.Run("创建投票地址", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		addr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamVote{
			Delegate: delegateTemplateAddress,
			Owner:    voteAddr.Address,
		})
		w.Nil(err)
		voteTemplateAddr = *addr
		log.Println("vote template addr:", voteTemplateAddr)
	})

	t.Run("给他人投票", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		{ //首先给投票用户准备点资产
			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   minerAddr,
				To:     voteAddr.Address,
				Amount: registeredAssets,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(voteAddr.Address, registeredAssets, client, "给voter准备原始资产"))
		}

		_, err := signAndSendtransaction(bbrpc.CmdSendfrom{
			From:   voteAddr.Address,
			To:     voteTemplateAddr,
			Amount: amount,
		}, []string{voteAddr.Privkey}, client, voteTemplateAddr)
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(voteTemplateAddr, amount, client, "验证voter投票成功"))
	})

	if 2 > 1 {
		return
	}

	voterBalance := registeredAssets - amount
	amount--
	t.Run("赎回投票", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		_, err := signAndSendtransaction(bbrpc.CmdSendfrom{
			From:   voteTemplateAddr,
			To:     voteAddr.Address,
			Amount: amount,
		}, []string{voteAddr.Privkey}, client, voteTemplateAddr)
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(voteAddr.Address, voterBalance+amount-0.01, client, "验证voter赎回成功"))
	})
	log.Println("done")
	time.Sleep(5 * time.Second)
}

func TestGenPrefixAddr(t *testing.T) {
	// t.Skip("使用时打开")
	const prefix = "1m1n"
	const n = 1 //要几个
	count := 0
	for x := 0; count < n; x++ {
		p, _ := gobbc.MakeKeyPair()
		if strings.HasPrefix(p.Addr, prefix+strconv.Itoa(count)) {
			fmt.Printf("\n%#v\n", p)
			count++
		}
		if x%20000 == 0 {
			fmt.Print(".")
		}
	}
}

func TestPOSMultisig(t *testing.T) {
	// 创建代理地址
	// 给他投票
	// 赎回

	// 创建多签地址
	// 创建交易
	// 签名

	if testing.Short() {
		t.Skip("skip short")
	}

	w := gobbc.TW{T: t}
	const pass = "123"
	const registeredAssets = 123.4

	killNode, client, minerAddr := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: false, KeepTmpDirInKill: true,
	})
	// bigbang-cli -rpcuser=rpcusr -rpcpassword=pwd -rpcport=19906
	_ = killNode
	defer killNode()

	ma0, ma1, ma2 := mAddr0, mAddr1, mAddr2
	for _, x := range []gobbc.AddrKeyPair{ma0, ma1, ma2} {
		_, err := client.Importprivkey(x.Privk, pass)
		w.Nil(err)
		_, _ = client.Unlockkey(x.Pubk, pass, nil)
	}

	w.Nil(bbrpc.Wait4nBlocks(1, client))
	var multisigAddress string
	{ //创建多签地址,并为其准备注册资金
		ret, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
			Required: 2, Pubkeys: []string{ma0.Pubk, ma1.Pubk, ma2.Pubk},
		})
		w.Nil(err)
		multisigAddress = *ret

		w.Nil(bbrpc.Wait4balanceReach(minerAddr, registeredAssets, client, "矿工资金"))
		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			From:   minerAddr,
			To:     multisigAddress,
			Amount: registeredAssets,
		})
		w.Nil(err)
		w.Nil(bbrpc.Wait4balanceReach(multisigAddress, registeredAssets, client, "多签地址注册资金到账"))
	}

	delegateAddr, dposMine2Addr, ownerAddr := tAddr0, tAddr1, tAddr2
	w.Nil(bbrpc.Wait4balanceReach(minerAddr, 100, client, "矿工挖到基础资本"))
	for _, x := range []bbrpc.AddrKeypair{
		tAddr0, tAddr1, tAddr2,
	} {
		_, err := client.Importprivkey(x.Privkey, pass)
		w.Nil(err)
		_, _ = client.Unlockkey(x.Pubkey, pass, nil)
	}

	var delegateTemplateAddress string
	t.Run("创建DPOS delegate模版", func(_t *testing.T) {
		w := gobbc.TW{T: _t}
		tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamDelegate{
			Delegate: delegateAddr.Pubkey,
			Owner:    dposMine2Addr.Address,
		})
		w.Nil(err)
		delegateTemplateAddress = *tplAddr
		log.Println("delegate tpl addr:", delegateTemplateAddress)
	})

	amount := 10.0
	amount++
	t.Run("delegator 投票给自己", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		{ //首先给该地址准备资金
			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   minerAddr,
				To:     dposMine2Addr.Address,
				Amount: registeredAssets,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(dposMine2Addr.Address, registeredAssets, client, "给delegator准备原始资产"))
		}
		_, err := client.Sendfrom(bbrpc.CmdSendfrom{
			From:   dposMine2Addr.Address,
			To:     delegateTemplateAddress,
			Amount: amount,
		})
		w.Nil(err)
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(delegateTemplateAddress, amount, client, "验证给自己投票成功"))
	})

	var voteTemplateAddr string
	amount++

	t.Run("多签地址投票给他人，owner为一般公钥地址", func(_t *testing.T) {
		t.Run("创建投票地址,owner为一般地址", func(_t *testing.T) {
			w := gobbc.TW{T: _t}
			addr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamVote{
				Delegate: delegateTemplateAddress,
				Owner:    ownerAddr.Address,
			})
			w.Nil(err)
			voteTemplateAddr = *addr
			log.Println("vote template addr:", voteTemplateAddr)
		})
		t.Run("用多签地址给他人投票", func(_t *testing.T) {
			txP, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
				From:   multisigAddress,
				To:     voteTemplateAddr,
				Amount: amount,
			})
			w.Nil(err)

			log.Println("tx multisig->vote", *txP)
			rpcSignTX, err := client.Signtransaction(*txP)
			w.Nil(err)
			log.Println("tx multisig->vote signed", rpcSignTX.Hex)

			_, err = client.Sendtransaction(rpcSignTX.Hex)
			w.Nil(err)
			// _, err := client.Sendfrom(bbrpc.CmdSendfrom{
			// 	From:   multisigAddress,
			// 	To:     voteTemplateAddr,
			// 	Amount: amount,
			// })
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(voteTemplateAddr, amount, client, "验证voter投票成功"))
		})

		amount--
		t.Run("赎回投票", func(_t *testing.T) {
			w := gobbc.TW{T: _t}

			_, err := client.Sendfrom(bbrpc.CmdSendfrom{
				From:   voteTemplateAddr,
				To:     ownerAddr.Address,
				Amount: amount,
			})
			w.Nil(err)
			w.Nil(bbrpc.Wait4nBlocks(1, client))
			w.Nil(bbrpc.Wait4balanceReach(ownerAddr.Address, amount, client, "验证voter赎回成功"))
		})
	})
	// t.Run("多签地址投票给他人，owner为自己（多签）", func(_ *testing.T) {
	// 	t.Run("创建投票地址,owner为多签地址", func(_t *testing.T) {
	// 		w := gobbc.TW{T: _t}
	// 		addr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamVote{
	// 			Delegate: delegateTemplateAddress,
	// 			Owner:    multisigAddress,
	// 		})
	// 		w.Nil(err)
	// 		voteTemplateAddr = *addr
	// 		log.Println("vote template addr:", voteTemplateAddr)
	// 	})
	// 	t.Run("用多签地址给他人投票", func(_t *testing.T) {
	// 		{
	// 			txP, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
	// 				From:   multisigAddress,
	// 				To:     voteTemplateAddr,
	// 				Amount: amount,
	// 			})
	// 			w.Nil(err)

	// 			log.Println("tx multisig->vote", *txP)
	// 			rpcSignTX, err := client.Signtransaction(*txP)
	// 			w.Nil(err)
	// 			log.Println("tx multisig->vote signed", rpcSignTX.Hex)
	// 			_, err = client.Sendtransaction(rpcSignTX.Hex)
	// 			w.Nil(err)
	// 		}

	// 		// _, err := client.Sendfrom(bbrpc.CmdSendfrom{
	// 		// 	From:   multisigAddress,
	// 		// 	To:     voteTemplateAddr,
	// 		// 	Amount: amount,
	// 		// })
	// 		// w.Nil(err)
	// 		w.Nil(bbrpc.Wait4nBlocks(1, client))
	// 		w.Nil(bbrpc.Wait4balanceReach(voteTemplateAddr, amount, client, "验证voter投票成功"))
	// 	})

	// 	amount--
	// 	t.Run("多签地址赎回投票到多签地址", func(_t *testing.T) {
	// 		w := gobbc.TW{T: _t}

	// 		{
	// 			txP, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
	// 				From:   voteTemplateAddr,
	// 				To:     multisigAddress,
	// 				Amount: amount,
	// 			})
	// 			w.Nil(err)

	// 			log.Println("tx vote->multisig", *txP)
	// 			rpcSignTX, err := client.Signtransaction(*txP)
	// 			w.Nil(err)
	// 			log.Println("tx vote->multisig signed", rpcSignTX.Hex)
	// 			_, err = client.Sendtransaction(rpcSignTX.Hex)
	// 			w.Nil(err)
	// 		}

	// 		// _, err := client.Sendfrom(bbrpc.CmdSendfrom{
	// 		// 	From:   voteTemplateAddr,
	// 		// 	To:     ownerAddr.Address,
	// 		// 	Amount: amount,
	// 		// })
	// 		// w.Nil(err)
	// 		w.Nil(bbrpc.Wait4nBlocks(1, client))
	// 		// w.Nil(bbrpc.Wait4balanceReach(ownerAddr.Address, amount, client, "验证voter赎回成功"))
	// 	})
	// })

	log.Println("done")
	time.Sleep(5 * time.Second)
}

// 测试多签地址作为owner的多个出块商
// 使用multisig作为owner创建delegate 模版地址
// 给自己投票
// 创建多个模版地址
// 取回投票
func TestPOSMultisigMultiDelegate(t *testing.T) {
	if testing.Short() {
		t.Skip("skip short")
	}

	w := gobbc.TW{T: t}
	const pass = "123"
	const registeredAssets = 123.4

	killNode, client, minerAddr := bbrpc.TesttoolRunServerAndBeginMint(t, bbrpc.RunBigBangOptions{
		NewTmpDir: true, NotPrint2stdout: false, KeepTmpDirInKill: true,
	})
	// bigbang-cli -rpcuser=rpcusr -rpcpassword=pwd -rpcport=19906
	_ = killNode
	defer killNode()

	da0, da1, da2, outAddr := tAddr0, tAddr1, tAddr2, tAddr3 //3个出块私钥
	_, err := client.Importprivkey(outAddr.Privkey, pass)
	w.Nil(err)
	_, _ = client.Unlockkey(outAddr.Pubkey, pass, nil)

	ma0, ma1, ma2 := mAddr0, mAddr1, mAddr2
	for _, x := range []gobbc.AddrKeyPair{ma0, ma1, ma2} {
		_, err := client.Importprivkey(x.Privk, pass)
		w.Nil(err)
		_, _ = client.Unlockkey(x.Pubk, pass, nil)
	}

	w.Nil(bbrpc.Wait4balanceReach(minerAddr, 1000, client, "矿工挖到基础资本"))
	var multisigAddress string
	{ //创建多签地址,并为其准备注册资金
		ret, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamMultisig{
			Required: 2, Pubkeys: []string{ma0.Pubk, ma1.Pubk, ma2.Pubk},
		})
		w.Nil(err)
		multisigAddress = *ret

		_, err = client.Sendfrom(bbrpc.CmdSendfrom{
			From:   minerAddr,
			To:     multisigAddress,
			Amount: registeredAssets,
		})
		w.Nil(err)
		w.Nil(bbrpc.Wait4balanceReach(multisigAddress, registeredAssets, client, "多签地址注册资金到账"))
	}

	var delegateAddrList [3]string
	t.Run("创建多个DPOS delegate模版", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		for i, x := range []bbrpc.AddrKeypair{da0, da1, da2} {
			tplAddr, err := client.Addnewtemplate(bbrpc.AddnewtemplateParamDelegate{
				Delegate: x.Pubkey,
				Owner:    multisigAddress,
			})
			w.Nil(err)
			delegateAddrList[i] = *tplAddr

		}
		log.Println("delegate tpl addr:", delegateAddrList)
	})

	amount := 10.0
	t.Run("multisig 投票给自己", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		for _, delegateAddr := range delegateAddrList {
			_, err := signAndSendtransaction(bbrpc.CmdSendfrom{
				From:   multisigAddress,
				To:     delegateAddr,
				Amount: amount,
			}, []string{ma0.Privk, ma1.Privk}, client, multisigAddress)
			// _, err := client.Sendfrom(bbrpc.CmdSendfrom{
			// 	From:   multisigAddress,
			// 	To:     delegateAddr,
			// 	Amount: amount,
			// })
			w.Nil(err)
		}
		w.Nil(bbrpc.Wait4nBlocks(1, client))

		for _, delegateAddr := range delegateAddrList {
			w.Nil(bbrpc.Wait4balanceReach(delegateAddr, amount, client, "验证给自己投票成功"))
		}
	})

	amount--
	t.Run("multisig赎回投票", func(_t *testing.T) {
		w := gobbc.TW{T: _t}

		for _, delegateAddr := range delegateAddrList {
			_, err := signAndSendtransaction(bbrpc.CmdSendfrom{
				From:   delegateAddr,
				To:     outAddr.Address,
				Amount: amount,
			}, []string{ma1.Privk, ma2.Privk}, client, delegateAddr, multisigAddress)
			// _, err := client.Sendfrom(bbrpc.CmdSendfrom{
			// 	From:   delegateAddr,
			// 	To:     outAddr.Address,
			// 	Amount: amount,
			// })
			w.Nil(err)
		}
		w.Nil(bbrpc.Wait4nBlocks(1, client))
		w.Nil(bbrpc.Wait4balanceReach(outAddr.Address, 3*amount, client, "验证voter赎回成功"))
	})

	log.Println("done")
	time.Sleep(5 * time.Second)
}

// - delegate template owner 可以是多签地址吗？
// - vote template owner 可以是多签地址吗？
