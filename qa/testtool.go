package qa

import (
	"fmt"

	"github.com/dabankio/bbrpc"
	"github.com/lomocoin/gobbc"
)

var changeTxVersionTo = "ffff" //某些链上要改tx版本

func signAndSendtransaction(cmd bbrpc.CmdSendfrom, privateKeys []string, client *bbrpc.Client, tplAddress ...string) (*string, error) {
	txP, err := client.Createtransaction(bbrpc.CmdCreatetransaction{
		From:   cmd.From,
		To:     cmd.To,
		Amount: cmd.Amount,
	})
	if err != nil {
		return nil, err
	}

	if changeTxVersionTo != "" {
		_tx := changeTxVersionTo + (*txP)[4:]
		txP = &_tx
	}
	rawTX, err := gobbc.DecodeRawTransaction(*txP, false)
	if err != nil {
		return nil, err
	}
	if len(tplAddress) == 0 {
		err = rawTX.SignWithPrivateKey("", privateKeys[0])
		if err != nil {
			return nil, err
		}
	} else { //如果提供了模版地址，则附加模版地址数据（在2种情况下使用: to 位vote template, from为template）
		templateData := ""
		for i, tpl := range tplAddress {
			addrInfo, err := client.Validateaddress(tpl)
			if err != nil {
				return nil, err
			}
			if i > 0 {
				templateData = templateData + ","
			}
			templateData = templateData + addrInfo.Addressdata.Templatedata.Hex
			
		}
		for _, privateKey := range privateKeys {
			err = rawTX.SignWithPrivateKey(templateData, privateKey)
			if err != nil {
				return nil, err
			}
		}
	}
	signedTx, err := rawTX.Encode(true)
	if err != nil {
		return nil, err
	}
	txid, err := client.Sendtransaction(signedTx)
	if err != nil {
		rpcSignResult, _ := client.Signtransaction(*txP)
		fmt.Printf("sdk sign not ok:\ntx : %s\nsdk: %s\nrpc: %s\n", *txP, signedTx, rpcSignResult.Hex)
	}
	return txid, err
}
