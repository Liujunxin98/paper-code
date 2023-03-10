package main

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// g *twist.G1Affine, hi []*twist.G2Affine, hij []*twist.G2Affine, err error
var g1generator bn254.G1Affine
var h1list []*bn254.G1Affine
var h12list [][]*bn254.G1Affine

func VC_KeyGen(q int) {
	// 函数体
	a, _, _, _ := bn254.Generators()

	g1generator.FromJacobian(&a)
	fmt.Printf("generator point: (%s, %s)\n", g1generator.X.String(), g1generator.Y.String())

	Z := make([]big.Int, q)
	for i := 0; i < q; i++ {
		var randz fr.Element
		randz.SetRandom()
		var randzBigInt big.Int
		randzBigInt = *randz.BigInt(&randzBigInt)
		Z[i] = randzBigInt
		fmt.Printf("randz: %x\n", randzBigInt.Bytes())
	}

	h1list = make([]*bn254.G1Affine, 50)
	h12list = make([][]*bn254.G1Affine, 50)
	for i := range h12list {
		h12list[i] = make([]*bn254.G1Affine, q)
	}
	for i := 0; i < q; i++ {
		var temph1 bn254.G1Affine
		temph1.ScalarMultiplication(&g1generator, &Z[i])
		h1list[i] = &temph1
		for j := 0; j < q; j++ {
			temph1.ScalarMultiplication(&temph1, &Z[j])
			h12list[i][j] = &temph1
			fmt.Printf("Public key: (%d,%d): (%s, %s)\n", i, j, h12list[i][j].X.String(), h12list[i][j].Y.String())
		}
	}

}

var Message []big.Int

func genMessage(q int) {

	Message = make([]big.Int, q)
	for i := 0; i < q; i++ {
		var randz fr.Element
		randz.SetRandom()
		var randzBigInt big.Int
		randzBigInt = *randz.BigInt(&randzBigInt)
		Message[i] = randzBigInt
		fmt.Printf("randz: %x\n", randzBigInt.Bytes())
	}
}

func main() {
	VC_KeyGen(50)

	/*
		// 生成私钥
		var privateKey fr.Element
		privateKey.SetRandom()
		var privateKeyBigInt big.Int
		privateKeyBigInt = *privateKey.BigInt(&privateKeyBigInt)
		fmt.Printf("Private key: %x\n", privateKeyBigInt.Bytes())
		//获取G2曲线上的生成元
		_, b, _, _ := bn254.Generators()
		var g2generator bn254.G2Affine
		g2generator.FromJacobian(&b)
		fmt.Printf("generator point: (%s, %s)\n", g2generator.X.String(), g2generator.Y.String())
		//根据生成元和私钥计算公钥
		var publicKey bn254.G2Affine
		publicKey.ScalarMultiplication(&g2generator, &privateKeyBigInt)
		fmt.Printf("Public key: (%s, %s)\n", publicKey.X.String(), publicKey.Y.String())
		//生成消息并哈希

		numRuns := 1000
		signtotalTime := time.Duration(0)
		verifytotalTime := time.Duration(0)
		for i := 0; i < numRuns; i++ {
			startTime := time.Now()
			message := []byte("hello, world")
			dst := []byte("game channel")
			var hm bn254.G1Affine
			hm, err := bn254.EncodeToG1(message, dst)
			if err != nil {
				fmt.Println("哈希失败：", err)
				return
			}
			//fmt.Printf("hash to g1 point: (%s, %s)\n", hm.X.String(), hm.Y.String())
			//利用私钥对消息签名
			var signature bn254.G1Affine
			signature.ScalarMultiplication(&hm, &privateKeyBigInt)
			//fmt.Printf("signature point: (%s, %s)\n", signature.X.String(), signature.Y.String())

			runTime := time.Since(startTime)
			signtotalTime += runTime

			verifystartTime := time.Now()
			//验证签名
			var flag bool
			flag, err = bn254.PairingCheck([]bn254.G1Affine{hm, signature}, []bn254.G2Affine{g2generator, publicKey})
			if err != nil {
				fmt.Println("配对错误：", err)
				return
			}
			fmt.Println(!flag)
			verifyrunTime := time.Since(verifystartTime)
			verifytotalTime += verifyrunTime
		}
		signavgTime := signtotalTime / time.Duration(numRuns)
		fmt.Printf("签名平均运行时间为：%v\n", signavgTime)
		verifyavgTime := verifytotalTime / time.Duration(numRuns)
		fmt.Printf("验证签名平均运行时间为：%v\n", verifyavgTime)
	*/
}
