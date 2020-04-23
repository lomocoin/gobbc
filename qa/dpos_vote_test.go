package qa

import (
	"fmt"
	"math"
	"testing"

	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
	"github.com/stretchr/testify/require"
)

func client(t *testing.T) *bbrpc.Client {
	rpc, err := bbrpc.NewClient(&bbrpc.ConnConfig{
		Host:       "192.168.50.5:9914",
		User:       "coinrpc",
		Pass:       "dabank",
		DisableTLS: true,
	})
	require.NoError(t, err)
	return rpc
}

func TestDposVote2myself(t *testing.T) {
	r := require.New(t)
	rpc := client(t)

	// # 给自己投票
	// sendfrom 1cswxkz63c63fmwtw3drdbja902p7ve4jxsyvq8sg19aq0fa0dhpw5nrf 20m07ex2d44pcww90sb8c1e5ekkdfqd4c6ty9n2eqd1pnba6b3fxne75b  220
	var (
		miner = gobbc.AddrKeyPair{
			Privk: "9eaa8f024667319c747e7a66132bb729d44e647474328e3d31dd428b5da9339e",
			Addr:  "1cswxkz63c63fmwtw3drdbja902p7ve4jxsyvq8sg19aq0fa0dhpw5nrf",
		}
		delegateAddr = "20m07ex2d44pcww90sb8c1e5ekkdfqd4c6ty9n2eqd1pnba6b3fxne75b"
	)

	// 给自己投票
	tx, err := rpc.Createtransaction(bbrpc.CmdCreatetransaction{
		From:   miner.Addr,
		To:     delegateAddr,
		Amount: 12.3,
	})
	r.NoError(err)

	rawtx, err := gobbc.DecodeRawTransaction(*tx, true)
	r.NoError(err)
	rawtx.Version = math.MaxUint16
	err = rawtx.SignWithHexedKey(miner.Privk)
	r.NoError(err)
	signedTX, err := rawtx.Encode(true)
	r.NoError(err)
	txid, err := rpc.Sendtransaction(signedTX)
	r.NoError(err)
	fmt.Println("vote to myself txid", *txid)
}
func TestDposVote2tpl(t *testing.T) {
	r := require.New(t)
	rpc := client(t)

	// 2）投票
	// 命令：
	// sendfrom 1s0qrhxm0h1kqnadj562j9exd68w4rcnn3g0f0tdk42aq9e7wnvsx6cn4 20w0d4wkdnjvz5j8r5036q4wm0cmn8wryj10x0cdq76wmq1s5vv2qm9mt 10086
	// >>5e85535eb14d6d2a6244a9b2ad3afb48e5ef74496ae0638ab479082400aeaafa
	var (
		owner = gobbc.AddrKeyPair{
			Privk: "98ed183a479a82148baab8a7abfcb0d508704e3cae65d816d97f30f3a1e261f3",
			Addr:  "1s0qrhxm0h1kqnadj562j9exd68w4rcnn3g0f0tdk42aq9e7wnvsx6cn4",
		}
		voteAddr = "20w0d4wkdnjvz5j8r5036q4wm0cmn8wryj10x0cdq76wmq1s5vv2qm9mt"
	)

	// 给别人投票
	tx, err := rpc.Createtransaction(bbrpc.CmdCreatetransaction{
		From:   owner.Addr,
		To:     voteAddr,
		Amount: 12.3,
	})
	r.NoError(err)

	rawtx, err := gobbc.DecodeRawTransaction(*tx, true)
	r.NoError(err)
	fmt.Println("create tx", *tx)
	rawtx.Version = math.MaxUint16
	err = rawtx.SignWithHexedKey(owner.Privk)
	r.NoError(err)
	signedTX, err := rawtx.Encode(true)
	r.NoError(err)
	fmt.Println("signed TX:", signedTX)
	txid, err := rpc.Sendtransaction(signedTX)
	r.NoError(err)
	fmt.Println("vote to template txid", *txid)
}
func TestDposVoteRedeem(t *testing.T) {
	r := require.New(t)
	rpc := client(t)

	// 赎回
	// 说明：只能由参与投票的地址进行赎回操作，且相应的钱包需处于解锁状态
	// sendfrom 20w0d4wkdnjvz5j8r5036q4wm0cmn8wryj10x0cdq76wmq1s5vv2qm9mt 1s0qrhxm0h1kqnadj562j9exd68w4rcnn3g0f0tdk42aq9e7wnvsx6cn4 87 1
	// >>5e8554cd52fb2a840f59c895d2352e94f7521ff27fc15849b4f8118da226eb1c

	var (
		owner = gobbc.AddrKeyPair{
			Privk: "9eaa8f024667319c747e7a66132bb729d44e647474328e3d31dd428b5da9339e",
			Addr:  "1cswxkz63c63fmwtw3drdbja902p7ve4jxsyvq8sg19aq0fa0dhpw5nrf",
		}
		voteAddr = "20w0d4wkdnjvz5j8r5036q4wm0cmn8wryj10x0cdq76wmq1s5vv2qm9mt"
	)

	// 赎回
	tx, err := rpc.Createtransaction(bbrpc.CmdCreatetransaction{
		From:   voteAddr,
		To:     owner.Addr,
		Amount: 12.3,
	})
	r.NoError(err)

	fmt.Println("createtransaction", *tx)
	rawtx, err := gobbc.DecodeRawTransaction(*tx, true)
	r.NoError(err)
	rawtx.Version = math.MaxUint16
	err = rawtx.SignWithHexedKey(owner.Privk)
	r.NoError(err)
	signedTX, err := rawtx.Encode(true)
	r.NoError(err)
	fmt.Println("signed TX:", signedTX)
	txid, err := rpc.Sendtransaction(signedTX)
	r.NoError(err)
	fmt.Println("vote to myself txid", *txid)
}

func TestSendfrom(t *testing.T) {
	r := require.New(t)
	rpc := client(t)
	var (
		owner = gobbc.AddrKeyPair{
			Privk: "98ed183a479a82148baab8a7abfcb0d508704e3cae65d816d97f30f3a1e261f3",
			Pubk:  "f3aefcb8749520b369f0001cb5324c3832adbb248529b2a97a678880f6882fc8",
			Addr:  "1s0qrhxm0h1kqnadj562j9exd68w4rcnn3g0f0tdk42aq9e7wnvsx6cn4",
		}
		toAddr = "1sxs9gnbxs7nfb0m4xrmwkw3ew1dzg9hmv56e09dndd1rt0bbqwy9f6gv"
	)

	// 给自己投票
	tx, err := rpc.Createtransaction(bbrpc.CmdCreatetransaction{
		From:   owner.Addr,
		To:     toAddr,
		Amount: 12.3,
	})
	r.NoError(err)
	fmt.Println("rawtx:", *tx)

	rawtx, err := gobbc.DecodeRawTransaction(*tx, false)
	r.NoError(err)
	fmt.Println("tx.version:", rawtx.Version)
	rawtx.Version = math.MaxUint16
	err = rawtx.SignWithHexedKey(owner.Privk)
	r.NoError(err)
	signedTX, err := rawtx.Encode(true)
	r.NoError(err)
	fmt.Println("signedTX:", signedTX)

	{ //用rpc签名
		_, _ = rpc.Unlockkey(owner.Pubk, "123", nil)
		// r.NoError(err)

		// rpcSign, err := rpc.Signtransaction(*tx)
		// r.NoError(err)
		// fmt.Println("rpc sign result:", rpcSign.Hex)
		// r.Equal(signedTX, rpcSign.Hex, "rpc 签名和sdk签名应该一致")
	}

	txid, err := rpc.Sendtransaction(signedTX)
	r.NoError(err)
	fmt.Println("sendfrom txid", txid)
}
