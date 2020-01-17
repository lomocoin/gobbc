#作为cli测试时的参考脚本

#tCryptonightAddr = AddrKeypair{ //冷钱包挖矿地址
#        Keypair: Keypair{Privkey: "eadae10eb384b4d090c10bf2469ee359e32c179026f616ebdf38318ccda5a068", 
#        Pubkey: "639ddcfda6e7357cb6543ecb328d6abd130daedaa26beb09bf0e34260f583d77"},
#        Address: "1ewyng3s66g7by2fbdehdnbgd2eypn39jscz59dkw6qktdzewknhsmk4t", //cryptonightaddress
#}
#tCryptonightKey = AddrKeypair{ //挖矿私钥
#        Keypair: Keypair{Privkey: "174c4fabefc9573c9cd506dff7f6cb0c54ecaaa63cc0d9f53da7e9c133a01c3a",//cryptonightkey
#        Pubkey: "ea34707897e6a9ec8e4038179a75fb29d1204a3a5bc4bd07c1c6454d3feac3f7"},
#        Address: "1yz1ymftd8q3c21xxrhdkmjh0t4mzpxct2ww413qcn7k9ey3g6knfswbw",
#}

rm -rf $TMPDIR/bigbang_data_tmp
mkdir $TMPDIR/bigbang_data_tmp
cd $TMPDIR/bigbang_data_tmp

bigbang -rpcpassword=pwd -cryptonightaddress=1ewyng3s66g7by2fbdehdnbgd2eypn39jscz59dkw6qktdzewknhsmk4t -datadir=$TMPDIR/bigbang_data_tmp -port=9900 -rpcport=9906 -debug -rpcuser=rpcusr -cryptonightkey=174c4fabefc9573c9cd506dff7f6cb0c54ecaaa63cc0d9f53da7e9c133a01c3a -testnet -listen4 >> out.log 2>&1 &

bigbang-cli -rpcport=9906 -rpcuser=rpcusr -rpcpassword=pwd 

addnewtemplate mint '{"mint": "ea34707897e6a9ec8e4038179a75fb29d1204a3a5bc4bd07c1c6454d3feac3f7", "spent": "1ewyng3s66g7by2fbdehdnbgd2eypn39jscz59dkw6qktdzewknhsmk4t"}'

importprivkey eadae10eb384b4d090c10bf2469ee359e32c179026f616ebdf38318ccda5a068 123
unlockkey 639ddcfda6e7357cb6543ecb328d6abd130daedaa26beb09bf0e34260f583d77 123

##{
#    "privkey" : "fb458fad91aee4a645127a52d238dd7dfad48c130f2cc3800a0c6e301dff0250",
#    "pubkey" : "5571be5beb45b0c4577fa9e44ef21ef879db1ba09a3e04207bd92f14e3f381ae"
#}
#bigbang> makekeypair 
##{
#    "privkey" : "1b59986f309b8c60bed48feaba26ba61d98c150dfd28b2af923caf6e1b1a250e",
#    "pubkey" : "290e74b8692619aefc2b792624aec461118b495267ffe3dcbb649b0e4587cee4"
#}
##{
#    "privkey" : "ae9f02888f08a06f0e59316e679597546a9e8f41ba078df6771dbcda314ca82a",
#    "pubkey" : "eb594ac0d833ebd677a5182b7d538bac6c67598067b967e15e6cf8067a2be025"
#}

importprivkey fb458fad91aee4a645127a52d238dd7dfad48c130f2cc3800a0c6e301dff0250 123
importprivkey 1b59986f309b8c60bed48feaba26ba61d98c150dfd28b2af923caf6e1b1a250e 123
importprivkey ae9f02888f08a06f0e59316e679597546a9e8f41ba078df6771dbcda314ca82a 123
unlockkey 5571be5beb45b0c4577fa9e44ef21ef879db1ba09a3e04207bd92f14e3f381ae 123
unlockkey 290e74b8692619aefc2b792624aec461118b495267ffe3dcbb649b0e4587cee4 123
unlockkey eb594ac0d833ebd677a5182b7d538bac6c67598067b967e15e6cf8067a2be025 123


addnewtemplate multisig '{"required":3,"pubkeys":["5571be5beb45b0c4577fa9e44ef21ef879db1ba09a3e04207bd92f14e3f381ae","290e74b8692619aefc2b792624aec461118b495267ffe3dcbb649b0e4587cee4", "eb594ac0d833ebd677a5182b7d538bac6c67598067b967e15e6cf8067a2be025"]}'

sendfrom 20g06z2bmwb71n9xg9zsv4vzay86ab7avt6n97hm6ra2z3rsbrtc2ncer 2080f88ecwsdkn812nwhmxv3a1p94v57n5jz8ec7b8ek7nrzp3cvqtqg7 100

getbalance
createtransaction 2080f88ecwsdkn812nwhmxv3a1p94v57n5jz8ec7b8ek7nrzp3cvqtqg7 1nt0z7rrm5zcqp8047tda06yvf7w1xwjewjmqyny4p12yppxye5axx7ry 23

decodetransaction
signtransaction

stop
pkill bigbang