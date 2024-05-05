package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/big"
	"net"

	"github.com/neekrasov/blind-signature/rsa"
	"github.com/neekrasov/blind-signature/tcp"

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
			var registrarPubKeyBytes []byte
			if err := tcp.Read(reader, &registrarPubKeyBytes); err != nil {
				fmt.Println("Failed to read  registrar public key:", err)
				return
			}

			fmt.Println("Parsing registrar public key...")
			registrarPublicKey := &rsa.PublicKey{}
			if err := json.Unmarshal(registrarPubKeyBytes, registrarPublicKey); err != nil {
				fmt.Println("Failed to parse registrar public key:", err.Error())
				return
			}
			fmt.Println("Registrar public key ", registrarPublicKey.E)

			fmt.Println("Getting vote...")
			var voteBytes []byte
			if err := tcp.Read(reader, &voteBytes); err != nil {
				fmt.Println("Failed to read vote:", err)
				return
			}
			vote := string(voteBytes)

			fmt.Println("Hashing vote ", vote)
			m, err := rsa.HashSHA256(vote)
			if err != nil {
				fmt.Println("Failed to hash sha-256 vote", err)
				return
			}
			fmt.Println("Hashed vote...")

			fmt.Println("Getting signature...")
			var signBytes []byte
			if err := tcp.Read(reader, &signBytes); err != nil {
				fmt.Println("Failed to read vote:", err)
				return
			}
			signature := new(big.Int).SetBytes(signBytes)
			fmt.Println("Signature ", signature)

			fmt.Println("Verify signature...")
			if !rsa.Verify(signature, m, registrarPublicKey) {
				fmt.Println("Verifiing digital signature fail")

				if err := tcp.Send(conn, []byte("0")); err != nil {
					fmt.Println("Error write 0 response")
					return
				}

				return
			}

			fmt.Println("Signature verified.")
			votes[vote]++
			fmt.Println("Voting results:", votes)

			if err := tcp.Send(conn, []byte("1")); err != nil {
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
