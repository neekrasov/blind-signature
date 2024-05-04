package main

import (
	"blind-signature/rsa"
	"blind-signature/tcp"
	"bufio"
	"fmt"
	"math/big"
	"net"
)

func Registrar() error {
	fmt.Println("Generate keys...")
	registrarPublicKey, registrarPrivateKey, err := rsa.GenerateKeys(256)
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	fmt.Println("Starting server...")
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		return fmt.Errorf("error starting server: %w", err)
	}
	defer ln.Close()
	fmt.Println("Server started. Waiting for connections...")

	for {
		clientConn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			clientReader := bufio.NewReader(conn)

			fmt.Println("Getting client public key...")
			var clientPublicKeyBytes []byte
			if err := tcp.Read(clientReader, &clientPublicKeyBytes); err != nil {
				fmt.Println("Failed to read client public key: ", err)
				return
			}

			fmt.Println("Parsing client public key...")
			clientPublicKey := &rsa.PublicKey{}
			if err := clientPublicKey.FromBytes(clientPublicKeyBytes); err != nil {
				fmt.Println("Failed to parse client public key: ", err)
				return
			}
			fmt.Println("Client public key", clientPublicKey.E())

			fmt.Println("Sending registrar public key ", registrarPublicKey.E())
			if err := tcp.Send(conn, registrarPublicKey.ToBytes()); err != nil {
				fmt.Println("Error sending public key: ", err)
				return
			}

			fmt.Println("Getting user vote...")
			var blindedMsgBytes []byte
			if err := tcp.Read(clientReader, &blindedMsgBytes); err != nil {
				fmt.Println("Failed to read blinded msg: ", err)
				return
			}

			blindedMsg := new(big.Int).SetBytes(blindedMsgBytes)
			fmt.Println("User vote ", blindedMsg)

			// blindedMsg = rsa.Encrypt(blindedMsg, registrarPublicKey) // (xr^eb)^da -> xr^eb

			fmt.Println("Signing message...")
			signature := rsa.Sign(blindedMsg, registrarPrivateKey) // σ(xr^eb) = (xr^eb)^db
			fmt.Println("Signature ", signature)

			fmt.Println("Sending signed message...")
			if err := tcp.Send(conn, signature.Bytes()); err != nil {
				fmt.Println("Error sending sign data: ", err)
				return
			}
		}(clientConn)
	}
}

func main() {
	if err := Registrar(); err != nil {
		fmt.Println("Registrar returned an error:", err)
	}
}
