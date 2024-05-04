package main

import (
	"blind-signature/rsa"
	"blind-signature/tcp"
	"bufio"
	"fmt"
	"math/big"
	"net"

	"github.com/pkg/errors"
)

func Counter() error {
	ln, err := net.Listen("tcp", ":8081")
	if err != nil {
		return errors.Wrap(err, "start counter server fail")
	}
	defer ln.Close()

	fmt.Println("Counter server started. Waiting for connections...")

	votes := make(map[string]int)
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("Error accepting connection:", err)
			continue
		}

		go func(conn net.Conn) {
			defer conn.Close()

			reader := bufio.NewReader(conn)

			fmt.Println("Getting registrar public key...")
			var registrarPubKeyMsg string
			if err := tcp.Read(reader, &registrarPubKeyMsg); err != nil {
				fmt.Println("Failed to read  registrar public key:", err)
				return
			}

			fmt.Println("Parsing registrar public key...")
			registrarPublicKey := &rsa.PublicKey{}
			if err := registrarPublicKey.FromBytes([]byte(registrarPubKeyMsg)); err != nil {
				fmt.Println("Failed to parse registrar public key:", err.Error())
				return
			}
			fmt.Println("Registrar public key ", registrarPublicKey.E())

			fmt.Println("Getting vote...")
			var vote string
			if err := tcp.Read(reader, &vote); err != nil {
				fmt.Println("Failed to read vote:", err)
				return
			}
			fmt.Println("Vote ", vote)

			fmt.Println("Hashing vote...")
			m, err := rsa.HashSHA256(vote)
			if err != nil {
				fmt.Println("Failed to hash sha-256 vote", err)
				return
			}
			fmt.Println("Hashed vote...")

			fmt.Println("Getting signature...")
			var signStr string
			if err := tcp.Read(reader, &signStr); err != nil {
				fmt.Println("Failed to read vote:", err)
				return
			}
			signature := new(big.Int).SetBytes([]byte(signStr))
			fmt.Println("Signature ", signature)

			fmt.Println("Verify signature...")
			if !rsa.Verify(signature, m, registrarPublicKey) {
				fmt.Println("Verifiing digital signature fail")

				if err := tcp.Send(conn, "0"); err != nil {
					fmt.Println("Error write 0 response")
					return
				}

				return
			}

			fmt.Println("Signature verified.")
			votes[vote]++
			fmt.Println("Voting results:", votes)

			if err := tcp.Send(conn, "1"); err != nil {
				fmt.Println("Error write 1 response")
				return
			}
		}(conn)
	}
}

func main() {
	if err := Counter(); err != nil {
		fmt.Println("Counter returned an error:", err)
		return
	}
}
