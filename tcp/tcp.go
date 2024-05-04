package tcp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
)

func Read(r *bufio.Reader, v *string) error {
	lengthBytes, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	lengthBytes = bytes.TrimSpace(lengthBytes)

	length, err := strconv.Atoi(string(lengthBytes))
	if err != nil {
		return err
	}

	msgBytes := make([]byte, length)
	if _, err = r.Read(msgBytes); err != nil {
		return err
	}

	*v = string(msgBytes)

	return nil
}

func Send(conn net.Conn, data string) error {
	fmt.Fprintln(conn, len(data))
	if _, err := conn.Write([]byte(data)); err != nil {
		return err
	}

	return nil
}
