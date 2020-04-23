package qa

import (
	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
)

//几组地址
var (
	_tPassphrase = "123"
	tAddr0       = bbrpc.AddrKeypair{
		Keypair: bbrpc.Keypair{Privkey: "195cd69eff4580ad2430f92d2c86865c596e72edb33f40df5d41c97883241c7c", Pubkey: "a7386f6cbe769fda91462637393970850ae7528d2cee5214c26cc4b27c014a65"},
		Address: "1cn502z5jrhpc452jxrp8tmq71a2q0e9s6wk4d4etkxvbwv3f72ksbkdn"}
	tAddr1 = bbrpc.AddrKeypair{
		Keypair: bbrpc.Keypair{Privkey: "3de774bfb200a46f6d969f5e080572859bc5d7b297fdb34471f55be3326b2153", Pubkey: "1fb8c0c79a506fd8fcca12065331110ae4aedceb2eac38f75379174c6a5b1bff"},
		Address: "1zwdnptjc2xwn7xsrngqeqq5ewg512cak0r9cnz6rdx89nhy0q0fstv2y"}
	tAddr2 = bbrpc.AddrKeypair{
		Keypair: bbrpc.Keypair{Privkey: "8c49b0f3788e07025303ef763e55d14781c09d43cb749628d26280f8f6912336", Pubkey: "5910534ab7629ccb73659df42afc3c382597223a9caa4040a687dbebbe1aa88a"},
		Address: "1ham1nfqbve3tcg20nae3m8mq4mw3sz1ayjepawybkhhbejjk21cvjnx3"}
	tAddr3 = bbrpc.AddrKeypair{
		Keypair: bbrpc.Keypair{Privkey: "5dd0705adf24f1177cedf2795521748358ec08b2d46ddb659f4f68e870433e60", Pubkey: "e4dcb0b8282298a43d5f8c5cbdd3bc27e7f6a44bf0be04e38301655c09038fdb"},
		Address: "1ve7g62awcm0r7rr4qvr4q97pwwkvsmxxbj65yfd4k0h2he5gvkj3d8dz"}

	mAddr0 = gobbc.AddrKeyPair{
		Addr:  "1mts0088pahxb2sgzzrszz6d4ng22x3cwbgtqefpy9gp8xhv5r6man2x2",
		Privk: "ec1616ec7f59cd3271efd1b36503f2d49d42aee8305d0d4a68c8f311348f2ee6",
		Pubk:  "a8c165c78e2c4cde3e77355c9c8d2e04aca499ff33fe1f66b17a54162100b2a6"}
	mAddr1 = gobbc.AddrKeyPair{
		Addr:  "1mts1tkmctj44y2arhwwm2qrhga4v5vaqtn5hdazjhw5ycanv60hpk5pe",
		Privk: "f3b294519985db57c35b772ffd5bf5e7169f70c7cbccee27202723fb2c5d27fd",
		Pubk:  "2330bb2ae60b8ff2ab164bd557edb28982115f41398f58094f88d48c4e1db2a6"}
	mAddr2 = gobbc.AddrKeyPair{
		Addr:  "1mts2vtj1qpvhjpqtxxjj5y6s3tydzr1vv8ksac4648hbqddp7t1pxhhe",
		Privk: "d7ee5d9eae07049c7d6ddaa61f911830f02602f3c3a955a2599d0fd427ab1920",
		Pubk:  "833eb6b5bb222286309527da3be0dfbc1ed9f82265effa5a19b7bd41ea2db2a6"}
)
