package btc

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// Example demonstrating how to prepare a raw transaction with多个收款地址。
func ExampleCreateRawTransactionWithOutputs() {
	privKeyBytes := bytes.Repeat([]byte{0x01}, 32)
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)
	wif, _ := btcutil.NewWIF(privKey, &chaincfg.TestNet3Params, true)

	wallet, _ := NewWallet(wif.String(), TestNet)

	receiver1, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160([]byte("receiver-1")), &chaincfg.TestNet3Params)
	receiver2, _ := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160([]byte("receiver-2")), &chaincfg.TestNet3Params)

	outputs := []PaymentOutput{
		{Address: receiver1.EncodeAddress(), Amount: 1500},
		{Address: receiver2.EncodeAddress(), Amount: 1200},
	}

	utxos := []UTXO{
		{TxID: strings.Repeat("0", 64), Vout: 0, Value: 3000},
	}

	rawTx, err := wallet.CreateRawTransactionWithOutputs(P2WPKH, outputs, utxos)
	if err != nil {
		fmt.Println("unexpected error:", err)
		return
	}

	fmt.Println(len(rawTx) > 0)
	// Output: true
}
