package main

import (
	"bytes"
	"encoding/hex"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

const (
	txId             = "1111111111111111111111111111111111111111111111111111111111111111" // test test
	vOut             = 0
	prevPkScr        = "bcrt1penhr9zzwv493ch3776mc863ur5k05wsr7a445wnftwq5tn2ktnyq2dlvm9"                                                                             // previous index of the Taproot contract output
	prevAmtSats      = int64(1000_0000)                                                                                                                               // Amount at the contract output (in sats)
	redeem2Hex       = "2103356c029ceb2ea7e904383523dc22f77fbf514091b0453794c4f7d1490b4b485dad210263e251962af36c688e867bc82b586cc8aa99ca1a5dd87ac522fa11945574364eac" // Redeem2 hex string (branch script, from Go contract creation)
	controlBlock2Hex = "c0378b9e02abc775c2ccf93ad0665e36515a9bf60d204834cd676377b14f03195931d7815b9a3b5b2e0ffef4a42db686e3ca7a063be7c8eb1afcb206914147c850"           // Control block hex string (from Go contract creation)
	sk_P_WIF         = "a2295afff6991226acdbecc6758a5ccbdd59ce65dba405c3037e3926cc98f295"
	sk_adapt_WIF     = "db4aa9f322803ae9a411fe8cf6a6c03c4275959e845e51d0540afd0280522282"
	sendAddrStr      = "bcrt1q7jsr7d6wsqvxsyc9vll2gq7v0uh7sn7h9z2kx6" // regtest address to receive funds
	feeSat           = int64(200)

	//U's part
	redeem1Hex       = "5ab1752103a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef0ac"
	controlBlock1Hex = "c1a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef016c5afd986099036b001ec964ab3dd3accb8f1faadc31837a8f6374dac3e986c"
	sk_U_WIF         = "df4e18e055e9ba60226b5b0710d823784b2b9664ac3ed2da34334cd146bf2d83"
	sk_QHex          = "2f4ffd174b82128d6b2555a411ac1f48c9ffead15faea7483b567c20d2e9face"
)

func ParseParams(redeemHex, controlBlockHex, skWIF, skAdaptWIF, tapAddrStr, sendAddrStr string) (*btcec.PrivateKey, *btcec.PrivateKey, []byte, []byte, []byte, []byte) {
	/*
		// for regtest
		wif, err := btcutil.DecodeWIF(skWIF)
		if err != nil {
			log.Fatalf("bad WIF: %v", err)
		}
		sk := wif.PrivKey
	*/
	skBytes, err := hex.DecodeString(skWIF)
	if err != nil {
		log.Fatalf("%v", err)
	}
	sk, _ := btcec.PrivKeyFromBytes(skBytes)

	redeem, err := hex.DecodeString(redeemHex)
	if err != nil {
		log.Fatalf("%v", err)
	}

	controlBlock, err := hex.DecodeString(controlBlockHex)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// parsing the Tproot contract address
	tapAddr, err := btcutil.DecodeAddress(tapAddrStr, &chaincfg.RegressionNetParams)
	if err != nil {
		log.Fatalf("%v", err)
	}

	prevTapAddr, err := txscript.PayToAddrScript(tapAddr)
	if err != nil {
		log.Fatalf("%v", err)
	}

	/*
		// destination address stuff for regtest
		sendAddr, err := btcutil.DecodeAddress(sendAddrStr, &chaincfg.RegressionNetParams)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pkScriptDst, err := txscript.PayToAddrScript(sendAddr)
		if err != nil {
			log.Fatalf("%v", err)
		} */

	pkScriptDst := make([]byte, 34) // remove this when testing with regtest

	var sk_adapt *btcec.PrivateKey
	if skAdaptWIF != "" && skAdaptWIF != " " {

		// for regtest
		/*
			wifAdapt, err := btcutil.DecodeWIF(skAdaptWIF)
			if err != nil {log.Fatalf("bad WIF: %v", err)}
			sk_adapt = wifAdapt.PrivKey
		*/

		skAdaptBytes, err := hex.DecodeString(skAdaptWIF)
		if err != nil {
			log.Fatalf("%v", err)
		}
		sk_adapt, _ = btcec.PrivKeyFromBytes(skAdaptBytes)
	}

	return sk, sk_adapt, redeem, controlBlock, prevTapAddr, pkScriptDst
}

// Creat an unsigned tx
func CreateTx(prevTxId string, vOut uint32, InAmt, fee int64, pkScriptDst []byte) (*wire.MsgTx, error) {

	tx := wire.NewMsgTx(wire.TxVersion)

	txHash, err := chainhash.NewHashFromStr(txId)
	if err != nil {
		log.Fatalf("%v", err)
	}

	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: *txHash, Index: vOut}, // prev output (Taproot contract) we're spending
		Sequence:         wire.MaxTxInSequenceNum,
	})

	tx.AddTxOut(&wire.TxOut{
		Value:    prevAmtSats - feeSat,
		PkScript: pkScriptDst,
	})

	return tx, nil
}

func SignTx(tx *wire.MsgTx, inIdx int, prevPkScript, redeemScript []byte, prevAmtSats int64, sk *btcec.PrivateKey) ([]byte, error) {

	sigHashes := txscript.NewTxSigHashes(tx, txscript.NewCannedPrevOutputFetcher(prevPkScript, prevAmtSats))

	/*
		return txscript.RawTxInTapscriptSignature(
			tx, sigHashes, inIdx, redeemScript, prevAmtSats,
			sk, txscript.SigHashDefault, nil, nil,
		) */

	// creating the tapleaf from redeem (P's or U's script branch)
	leaf := txscript.NewBaseTapLeaf(redeemScript)

	return txscript.RawTxInTapscriptSignature(
		tx,
		sigHashes,
		inIdx,
		prevAmtSats,
		prevPkScript,
		leaf,
		txscript.SigHashDefault,
		sk,
	)
}

func main() {
	/*
		conn := &rpcclient.ConnConfig{
			Host:         "127.0.0.1:18443", // regtest port
			User:         " ",  // user & pass credentails from the bitcoin.conf
			Pass:         " ",
			HTTPPostMode: true,
			DisableTLS:   true,
		}
		cli, err := rpcclient.New(conn, nil)
		if err != nil {log.Fatalf("rpc connect: %v", err)}
		defer cli.Shutdown()
	*/

	// U
	sk_U, _, redeem1, controlBlock1, prevTapAddr, pkScriptDst := ParseParams(redeem1Hex, controlBlock1Hex, sk_U_WIF, " ", prevPkScr, sendAddrStr)

	txU, err := CreateTx(txId, vOut, prevAmtSats, feeSat, pkScriptDst)
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	sig_U, err := SignTx(txU, 0, prevTapAddr, redeem1, prevAmtSats, sk_U)
	if err != nil {
		log.Fatalf("signing: %v", err)
	}

	txU.TxIn[0].Witness = wire.TxWitness{
		sig_U,
		redeem1,
		controlBlock1,
	}


	// P
	sk_P, sk_adapt, redeem2, controlBlock2, prevTapAddr, pkScriptDst := ParseParams(redeem2Hex, controlBlock2Hex, sk_P_WIF, sk_adapt_WIF, prevPkScr, sendAddrStr)
	tx, err := CreateTx(txId, vOut, prevAmtSats, feeSat, pkScriptDst)
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	/*  //test
	//script-path signature for redeem2 (BIP-341 Taproot)
	sigHashes := txscript.NewTxSigHashes(tx)
	sig_P, err := txscript.RawTxInTapscriptSignature(
		tx, sigHashes, 0, redeem2, prevAmtSats,
		sk_P, txscript.SigHashDefault, nil, nil,
	)
	if err != nil {
		log.Fatalf("signing: %v", err)
	}
	*/

	sig_P, err := SignTx(tx, 0, prevTapAddr, redeem2, prevAmtSats, sk_P) // P's signature
	if err != nil {
		log.Fatalf("signing: %v", err)
	}

	sig_adapt, err := SignTx(tx, 0, prevTapAddr, redeem2, prevAmtSats, sk_adapt) // P's adaptor signature
	if err != nil {
		log.Fatalf("signing: %v", err)
	}

	// Witness stack for P (script path: [sigP, sigAdapt, redeem2, controlBlock])
	tx.TxIn[0].Witness = wire.TxWitness{
		sig_P,
		sig_adapt,
		redeem2,
		controlBlock2,
	}

		// Second case; using key-path spend for U's transaction
	skQBytes, _ := hex.DecodeString(sk_QHex)
	sk_Q, _ := btcec.PrivKeyFromBytes(skQBytes) //sk_Q --> tweaked private key

	txKeyPath, err := CreateTx(txId, vOut, prevAmtSats, feeSat, pkScriptDst)
	if err != nil {
		log.Fatalf("err: %v", err)
	}

	// Sign the key-path spend Tx
	sigHash := txscript.NewTxSigHashes(txKeyPath, txscript.NewCannedPrevOutputFetcher(prevTapAddr, prevAmtSats))

	sig_Q, err := txscript.RawTxInTapscriptSignature(
		txKeyPath,
		sigHash,
		0,
		prevAmtSats,
		prevTapAddr,
		txscript.TapLeaf{},
		txscript.SigHashDefault,
		sk_Q,
	)
	if err != nil {
		log.Fatalf("signing key-path: %v", err)
	}
	txKeyPath.TxIn[0].Witness = wire.TxWitness{sig_Q}

	var (
		buf        bytes.Buffer
		bufU       bytes.Buffer
		bufKeyPath bytes.Buffer
	)

	// P
	err = tx.Serialize(&buf)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// U
	err = txU.Serialize(&bufU)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// U key-path spend
	err = txKeyPath.Serialize(&bufKeyPath)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// P
	rawHex := hex.EncodeToString(buf.Bytes())
	log.Printf("Raw spend tx: %s\n", rawHex)
	log.Printf("Transaction size: %d bytes", tx.SerializeSize())

	// U
	rawHexU := hex.EncodeToString(bufU.Bytes())
	log.Printf("U's raw spend tx: %s\n", rawHexU)
	log.Printf("Transaction size: %d bytes", txU.SerializeSize())

	// U key-path spend
	rawHexKeyPath := hex.EncodeToString(bufKeyPath.Bytes())
	log.Printf("U's key-path spend tx: %s\n", rawHexKeyPath)
	log.Printf("Transaction size: %d bytes", txKeyPath.SerializeSize())

}

/*
	test output (no WIF keys):

	2025/07/10 17:08:13 P's raw spend tx hex: 010000000001011111111111111111111111111111111111111111111111111111111111111111
	0000000000ffffffff01b89598000000000022000000000000000000000000000000000000000000000000000000000000000000
	0004406f96b11ac51c0d0e99374ac01452cfa87a2c8848a0e456b3a2e535a86e3a087cf7ead85eeaa64c535a2aef8378b891099b1
	415837f1ca1bb34969efc172f27a54076cfd79e25e48735110547608515c581957f69f77f1379121a0e851f3e11cea1661a75e8f9a
	af3e48faae114978b8dad5dbef59671ac38aff9c03b49b4c9157f462103356c029ceb2ea7e904383523dc22f77fbf514091b0453794
	c4f7d1490b4b485dad210263e251962af36c688e867bc82b586cc8aa99ca1a5dd87ac522fa11945574364eac41c0378b9e02abc775c2
	ccf93ad0665e36515a9bf60d204834cd676377b14f03195931d7815b9a3b5b2e0ffef4a42db686e3ca7a063be7c8eb1afcb206914147c85000000000

	2025/07/10 17:08:13 Transaction size: 364 bytes

 	2025/07/13 00:17:57 U's raw spend tx: 0100000000010111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01b895980000000000220000
	000000000000000000000000000000000000000000000000000000000000000003
	406aba9a3c50e19922e889481b6eee43b0bd234b38cba647da11228930d79422dd0d83f0dd6fed1b418ba88ee6bcaf30f800005e0b97796db5c36b842204
	ccba3a265ab1752103a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef0ac41c1a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8b
	f993b303cf32fbb4ef016c5afd986099036b001ec964ab3dd3accb8f1faadc31837a8f6374dac3e986c00000000
 
	2025/07/13 00:17:57 Transaction size: 267 bytes

 	2025/07/13 18:30:57 U's key-path spend tx: 0100000000010111111111111111111111111111111111111111111111111111111111111111110000000000ffffffff01b895980
	000000000220000000000000000000000000000000000000000000000000000000000000000000001403052ae3560ff98d859bef7
	df6d3e47ce2743c0b49038a86b452edcafb49edf1d8557d5b0b5fe7725ac6d3577f5a0f58858da7909262d690bcd91ae834863366c00000000
 
	2025/07/13 18:30:57 Transaction size: 162 bytes



*/
