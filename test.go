package main

import (
	"blind-signature/rsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

func main() {
	for {
		test_mask()
	}
}

func testSign() {
	clientPublicKey, _, err := rsa.GenerateKeys(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	registrarPublicKey, registrarPrivateKey, err := rsa.GenerateKeys(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	msg_str := "Hello World!"
	msg, err := rsa.HashSHA256(msg_str)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("msg = ", msg)
	fmt.Println()

	// Calc r^e
	r, err := rand.Int(rand.Reader, clientPublicKey.N())
	if err != nil {
		fmt.Println("Failed to generate r:", err.Error())
		return
	}
	fmt.Println("r =", r)
	r = rsa.Encrypt(r, clientPublicKey)
	fmt.Println("r^e =", r)

	// Calc s = mr^e mod n
	blindedMsg := new(big.Int).Mul(msg, r)
	blindedMsg.Mod(blindedMsg, clientPublicKey.N())
	fmt.Println("blindedMsg = mr^e mod n = ", blindedMsg)
	fmt.Println()

	// Calc blindedMsg^d mod n - грязная подпись.
	sign := rsa.Sign(blindedMsg, registrarPrivateKey)
	fmt.Println("sign = blindedMsg^d mod n = ", sign)

	// Calc r^-1
	rInverse, err := rsa.ModInverse(r, clientPublicKey.N())
	if err != nil {
		fmt.Println("Failed to get inverse r", err)
	}
	fmt.Println("rInverse = r^-1 =", rInverse)

	// Calc blindedMsg*r^-1 mod n
	originalMsg := new(big.Int).Mul(blindedMsg, rInverse)
	originalMsg.Mod(originalMsg, clientPublicKey.N())
	fmt.Println("originalMsg = blindedMsg * r^-1 mod n = ", originalMsg)

	// Calc sign*r^-1 mod n
	originalSign := new(big.Int).Mul(sign, rInverse)
	originalSign.Mod(originalSign, clientPublicKey.N())
	fmt.Println("original sign = sign * r^-1 mod n = ", originalSign)

	if !rsa.Verify(originalSign, msg, registrarPublicKey) {
		fmt.Println("verifiing digital signature fail: ", err)
		return
	}
}

func testInverse() {
	publicKey, _, err := rsa.GenerateKeys(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	msg_str := "Hello World!"
	msg, err := rsa.HashSHA256(msg_str)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("msg = ", msg)

	// Calc r^e
	r, err := rand.Int(rand.Reader, publicKey.N())
	if err != nil {
		fmt.Println("Failed to generate r:", err.Error())
		return
	}
	fmt.Println("r =", r)
	r = rsa.Encrypt(r, publicKey)
	fmt.Println("r^e =", r)

	// Calc s = mr^e mod n
	blindedMsg := new(big.Int).Mul(msg, r)
	blindedMsg.Mod(blindedMsg, publicKey.N())
	fmt.Println("blindedMsg = mr^e mod n = ", blindedMsg)

	// Calc r^-1
	rInverse, err := rsa.ModInverse(r, publicKey.N())
	if err != nil {
		fmt.Println("Failexd to get inverse r", err)
	}
	fmt.Println("rInverse = r^-1 =", rInverse)

	// Calc s*r^-1 mod n
	originalMsg := new(big.Int).Mul(blindedMsg, rInverse)
	originalMsg.Mod(originalMsg, publicKey.N())
	fmt.Println("originalMsg = blindedMsg * r^-1 mod n = ", originalMsg)
}

func test() {
	publicKey, privateKey, err := rsa.GenerateKeys(128)
	if err != nil {
		fmt.Println(err)
		return
	}

	msg_str := "Hello World!"
	msg, err := rsa.HashSHA256(msg_str)
	if err != nil {
		fmt.Println(err)
		return
	}

	encrypted := rsa.Encrypt(msg, publicKey)
	decrypted := rsa.Decrypt(encrypted, privateKey)

	signature := rsa.Sign(msg, privateKey)
	verified := rsa.Verify(signature, msg, publicKey)

	fmt.Println("msg=", msg, "encrypted=", encrypted, "decrypted=", decrypted, "signature=", signature, "verified = ", verified)

	fromBytesTest := &rsa.PublicKey{}
	if err := fromBytesTest.FromBytes(publicKey.ToBytes()); err != nil {
		fmt.Println("error parsing public key", err.Error())
	}
}

func test_mask() {
	// clientPublicKey, clientPrivateKey, err := rsa.GenerateKeys(128) // da
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	registrarPublicKey, registrarPrivateKey, err := rsa.GenerateKeys(128) // eb db
	if err != nil {
		fmt.Println(err)
		return
	}

	msg_str := "test"
	msg, err := rsa.HashSHA256(msg_str)
	if err != nil {
		fmt.Println(err)
		return
	}

	r, err := rand.Int(rand.Reader, registrarPublicKey.N()) // r
	if err != nil {
		fmt.Println("Failed to generate r:", err.Error())
		return
	}
	reb := rsa.Encrypt(r, registrarPublicKey) // r^eb
	blindedMsg := new(big.Int).Mul(msg, reb)  // r^eb -> xr^eb
	blindedMsg.Mod(blindedMsg, registrarPublicKey.N())

	fmt.Println(blindedMsg)
	// blindedMsg = rsa.Sign(blindedMsg, clientPrivateKey) // xr^eb -> (xr^eb)^da

	fmt.Println(blindedMsg)
	signedMsg := rsa.Sign(blindedMsg, registrarPrivateKey)

	rInverse, err := rsa.ModInverse(r, registrarPublicKey.N())
	if err != nil {
		panic(err)
	}

	signature := new(big.Int).Set(signedMsg)
	signature.Mul(signature, rInverse)
	signature.Mod(signature, registrarPublicKey.N())

	if !rsa.Verify(signature, msg, registrarPublicKey) {
		fmt.Println("verifiing digital signature fail: ", err)
		return
	}
	fmt.Println("signature verified")
}
