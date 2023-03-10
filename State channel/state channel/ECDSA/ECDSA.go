package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	// 生成一个secp256k1曲线的密钥对
	privateKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	publickey := privateKey.PublicKey
	// 要签名的消息
	message := "hello world"
	hashedMessage := sha256.Sum256([]byte(message))

	numRuns := 1000
	totalTime := time.Duration(0)
	verifytotalTime := time.Duration(0)
	for i := 0; i < numRuns; i++ {
		startTime := time.Now()
		// 生成签名
		r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashedMessage[:])
		if err != nil {
			log.Fatal(err)
		}
		// 将签名输出为16进制字符串
		signature := math.PaddedBigBytes(r, 32)
		signature = append(signature, math.PaddedBigBytes(s, 32)...)
		//signatureHex := hex.EncodeToString(signature)
		runTime := time.Since(startTime)
		totalTime += runTime

		verifystartTime := time.Now()
		ecdsa.Verify(&publickey, hashedMessage[:], r, s)
		verifyrunTime := time.Since(verifystartTime)
		verifytotalTime += verifyrunTime

	}
	avgTime := totalTime / time.Duration(numRuns)
	fmt.Printf("ECDSA签名平均运行时间为：%v\n", avgTime)
	verifyavgTime := verifytotalTime / time.Duration(numRuns)
	fmt.Printf("ECDSA验签平均运行时间为：%v\n", verifyavgTime)

	/*
		// 将签名输出为16进制字符串
		signature := math.PaddedBigBytes(r, 32)
		signature = append(signature, math.PaddedBigBytes(s, 32)...)
		signatureHex := hex.EncodeToString(signature)

		// 打印签名结果
		fmt.Printf("Signature for message '%s': %s\n", message, signatureHex)
	*/
}
