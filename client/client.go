package main

import (
	"blind-signature/rsa"
	"blind-signature/tcp"
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"

	"github.com/pkg/errors"
)

func Client() error {
	fmt.Println("Generate keys...")
	clientPublicKey, clientPrivateKey, err := rsa.GenerateKeys(512)
	if err != nil {
		return errors.Wrap(err, "failed to generate keys")
	}

	fmt.Println("Initialize connections...")
	registrarConn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		return errors.Wrap(err, "failed to initialize registrar connection")
	}
	defer registrarConn.Close()

	counterConn, err := net.Dial("tcp", "localhost:8081")
	if err != nil {
		return errors.Wrap(err, "failed to initialize counter connection")
	}
	defer counterConn.Close()

	registrarReader := bufio.NewReader(registrarConn)
	counterReader := bufio.NewReader(counterConn)

	fmt.Println("Sending client public key", clientPublicKey.E)
	clientPublicKeyBytes, err := json.Marshal(clientPublicKey)
	if err != nil {
		return errors.Wrap(err, "failed to marshal client public key")
	}
	if err := tcp.Send(registrarConn, clientPublicKeyBytes); err != nil {
		return errors.Wrap(err, "failed to send client's public key")
	}

	fmt.Println("Getting registrar public key...")
	var registrarPubKeyBytes []byte
	if err := tcp.Read(registrarReader, &registrarPubKeyBytes); err != nil {
		return errors.Wrap(err, "failed to read registrar's public key")
	}

	fmt.Println("Parsing registrar public key...")
	registrarPublicKey := &rsa.PublicKey{}
	if err := json.Unmarshal(registrarPubKeyBytes, registrarPublicKey); err != nil {
		return errors.Wrap(err, "failed to parse registrar public key")
	}
	fmt.Println("Registrar public key", registrarPublicKey.E)

	fmt.Print("Enter your message: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return errors.Wrap(err, "failed to read message")
	}
	vote := strings.TrimSpace(input)

	fmt.Println("Generating vote hash...")
	m, err := rsa.HashSHA256(vote)
	if err != nil {
		return errors.Wrap(err, "failed to generate m")
	}

	fmt.Println("Generating r...")
	r, err := rand.Int(rand.Reader, registrarPublicKey.N)
	if err != nil {
		return errors.Wrap(err, "failed to generate r")
	}

	fmt.Println("Generating blinded message (xr^eb)^da...")
	reb := rsa.Encrypt(r, registrarPublicKey) // r^eb
	blindedMsg := new(big.Int).Mul(m, reb)    // r^eb -> xr^eb
	blindedMsg.Mod(blindedMsg, registrarPublicKey.N)
	blindedMsg = rsa.Sign(blindedMsg, clientPrivateKey) // xr^eb ->(xr^eb)^da

	fmt.Println("Sending blinded message to registrar", blindedMsg)
	if err := tcp.Send(registrarConn, blindedMsg.Bytes()); err != nil {
		return errors.Wrap(err, "failed to send blinded msg to registrar")
	}

	fmt.Println("Getting registrar signature...")
	var signedMsgBytes []byte
	if err := tcp.Read(registrarReader, &signedMsgBytes); err != nil {
		return errors.Wrap(err, "error reading signed msg")
	}
	signature := new(big.Int).SetBytes(signedMsgBytes)
	fmt.Println("Registrar signature ", signature)

	fmt.Println("Generating rInverse...")
	rInverse, err := rsa.ModInverse(r, registrarPublicKey.N) // r^-1
	if err != nil {
		return errors.Wrap(err, "failed to calc modular inverse")
	}
	fmt.Println("rInverse ", rInverse)

	fmt.Println("Unwraping signature...")
	signature.Mul(signature, rInverse) // σ((xr^eb)^da) * r^-1 = σ(x)
	signature.Mod(signature, registrarPublicKey.N)
	fmt.Println("Signature ", signature)

	fmt.Println("Sending registrar public key to counter", registrarPublicKey.E)
	registrarPublicKeyBytes, err := json.Marshal(registrarPublicKey)
	if err != nil {
		return errors.Wrap(err, "failed to marshal registrar public key")
	}
	if err := tcp.Send(counterConn, registrarPublicKeyBytes); err != nil {
		return errors.Wrap(err, "failed to send msg to counter")
	}

	fmt.Println("Sending vote to counter ", vote)
	if err := tcp.Send(counterConn, []byte(vote)); err != nil {
		return errors.Wrap(err, "failed to send vote to counter")
	}

	fmt.Println("Sending signature to counter", signature)
	if err := tcp.Send(counterConn, signature.Bytes()); err != nil {
		return errors.Wrap(err, "failed to send signature to counter")
	}

	var b []byte
	if err := tcp.Read(counterReader, &b); err != nil {
		return errors.Wrap(err, "error reading counter response")
	}

	if b[0] == '1' {
		fmt.Println("OK")
		return nil
	}

	return errors.New("counter response was not OK")
}

func main() {
	if err := Client(); err != nil {
		fmt.Println("Client returned an error: ", err)
		return
	}
	fmt.Println("Your vote has been accepted")
}
