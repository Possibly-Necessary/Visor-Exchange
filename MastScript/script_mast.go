// Source: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

package main

import (
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	//"github.com/btcsuite/btcutil"
)

func KeyGen() (*btcec.PrivateKey, []byte) {
	sk, _ := btcec.NewPrivateKey()
	//pk := sk.PubKey().SerializeCompressed()[1:33] // this was 32 bytes
	pk := sk.PubKey().SerializeCompressed() // 33 bytes full point public key

	return sk, pk
}

func main() {

	sk_U, pk_U := KeyGen()
	sk_P, pk_P := KeyGen()
	sk_adapt, pk_adapt := KeyGen() // Pretend this is the full signature obtained off-chain from the pre-signatures

	/*
		Get the block height: bitcoin-cli -regtest getblockcount
		it should spit out a number, add + 2 (two blocks) for the lock time

	*/

	//lockHeight := int64( /*output from cli */ +2)

	lockHeight := int64(10) // test test test..

	// Leaf 1 for the first script condition/branch
	builder1 := txscript.NewScriptBuilder().
		AddInt64(lockHeight).
		AddOp(txscript.OP_CHECKLOCKTIMEVERIFY).
		AddOp(txscript.OP_DROP).
		AddData(pk_U).
		AddOp(txscript.OP_CHECKSIGVERIFY)
	redeem1, err := builder1.Script()
	if err != nil {
		log.Fatalf("failed: %v\n", err)
	}
	leaf1 := txscript.NewBaseTapLeaf(redeem1)

	//Leaf 2 for the second script condition/branch
	builder2 := txscript.NewScriptBuilder().
		AddData(pk_P).
		AddOp(txscript.OP_CHECKSIGVERIFY).
		AddData(pk_adapt).
		AddOp(txscript.OP_CHECKSIGVERIFY)
	redeem2, err := builder2.Script()
	if err != nil {
		log.Fatalf("failed: %v\n", err)
	}
	leaf2 := txscript.NewBaseTapLeaf(redeem2)

	// Build the MAST out of the two leaves
	tree := txscript.AssembleTaprootScriptTree(leaf1, leaf2)
	merkleRootHash := tree.RootNode.TapHash()

	intrKey, err := btcec.ParsePubKey(pk_U) // 33-bytes...?
	if err != nil {
		log.Fatalf("error parsing pk_U: %v\n", err)
	}

	// Control block for redeem 1
	leafHash1 := leaf1.TapHash()
	leafIndex1 := tree.LeafProofIndex[leafHash1]
	proof1 := tree.LeafMerkleProofs[leafIndex1]
	controlBlock1 := proof1.ToControlBlock(intrKey)
	cbBytes1, _ := controlBlock1.ToBytes()

	// Control block for redeem 2
	// Control block 33 + 32m bytes (BIP-341 spec)
	// where m is number of hashes in the Merkle path from leaf to the root / depth
	// Two leaves, so the control block will have 33 bytes (heaber + intrKey)
	// and 32 bytes (one sibling hash); so size of the control block of our tree = 33 + 32 × 1 = 65 bytes
	leafHash2 := leaf2.TapHash()
	leafIndex2 := tree.LeafProofIndex[leafHash2]
	proof2 := tree.LeafMerkleProofs[leafIndex2]
	controlBlock2 := proof2.ToControlBlock(intrKey)
	cbBytes2, _ := controlBlock2.ToBytes()

	// Taproot output key: Q = intrKey + hash(intrKey || merkleRootHash) * G
	// Q = interKey * g^(merkleRootHash)   ... ?
	outputKey := txscript.ComputeTaprootOutputKey(intrKey, merkleRootHash[:])

	xOnlykey := outputKey.SerializeCompressed()[1:33] //32-byte

	//taprootAddr, err := btcutil.NewAddressTaproot(outputKey.SerializeCompressed()[1:], &chaincfg.RegressionNetParams)
	taprootAddr, err := btcutil.NewAddressTaproot(xOnlykey, &chaincfg.RegressionNetParams) // always 32-byts
	if err != nil {
		log.Fatalf("error in taproot addr: %v", err)
	}

	fmt.Printf("MAST Taproot contract address: %s\n", taprootAddr.EncodeAddress())
	fmt.Printf("Merkle root size: %d bytes\n", len(merkleRootHash[:]))

	fmt.Println()

	fmt.Printf("Control block/Proof of leaf 1 in hex: %x\n", cbBytes1)
	fmt.Printf("Control block/Proof of leaf 1 size: %d bytes\n", len(cbBytes1)) // 65 bytes, tested
	fmt.Printf("Control block/Proof of leaf 2 in hex: %x\n", cbBytes2)
	fmt.Printf("Control block/Proof of leaf 2 size: %d bytes\n", len(cbBytes2)) // 65 bytes, tested

	fmt.Println()

	fmt.Printf("U's refund branch in hex: %x\n", redeem1)
	fmt.Printf("Refund branch size: %d bytes\n", len(redeem1)) // 38 bytes, tested

	fmt.Println()

	fmt.Printf("P's fund claim branch in hex: %x\n", redeem2)
	fmt.Printf("P's fund claim branch size: %d bytes\n", len(redeem2)) // 70 bytes, tested

	fmt.Println()

	log.Printf("U's pk in hex: %x\n", pk_U)
	log.Printf("P's pk in hex: %x\n", pk_P)
	log.Printf("Adaptor public key: %x\n", pk_adapt)

	fmt.Println()

	log.Printf("U's sk in hex: %x\n", sk_U.Serialize())
	log.Printf("P's sk in hex: %x\n", sk_P.Serialize())
	log.Printf("Adaptor sk in hex: %x\n", sk_adapt.Serialize())

}

/*

test output:

MAST Taproot contract address: bcrt1penhr9zzwv493ch3776mc863ur5k05wsr7a445wnftwq5tn2ktnyq2dlvm9
Merkle root size: 32 bytes

Control block/Proof of leaf 1 in hex: c1a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef016c5afd986099036b001ec964ab3dd3accb8f1faadc31837a8f6374dac3e986c
Control block/Proof of leaf 1 size: 65 bytes
Control block/Proof of leaf 2 in hex: c1a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef037c85d0a502a2721860380af20d7774cd469c0d20cc736e7dee61ef2565ed2fc
Control block/Proof of leaf 2 size: 65 bytes

U's refund branch in hex: 5ab1752103a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef0ac
Refund branch size: 38 bytes

P's fund claim branch in hex: 21030f64758579e661e20a1d57d21d1656c9843c550265df3ef8fa642bb293779f40ad2103da77cb7364bd55eb46597a41348f497c103865eac5b29d4d8a5225cbcf10e3ffac
P's fund claim branch size: 70 bytes

2025/07/10 01:46:44 U's pk in hex: 03a3f4c31f91193e5df06ebd0a8936c48ecbabd5cbabd8bf993b303cf32fbb4ef0
2025/07/10 01:46:44 P's pk in hex: 030f64758579e661e20a1d57d21d1656c9843c550265df3ef8fa642bb293779f40
2025/07/10 01:46:44 Adaptor public key: 03da77cb7364bd55eb46597a41348f497c103865eac5b29d4d8a5225cbcf10e3ff

2025/07/10 01:46:44 U's sk in hex: df4e18e055e9ba60226b5b0710d823784b2b9664ac3ed2da34334cd146bf2d83
2025/07/10 01:46:44 P's sk in hex: 8a0e04b0c0bc4cb7abe0164d87266c3d623bf6f5575f6ff319c79089fa7cccfc
2025/07/10 01:46:44 Adaptor sk in hex: 0406d2e4c53e5f307792bdfb49c01a2c66c92303e6ec633ffe0b887e7df0c979


*/
