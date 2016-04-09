package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func Send(conn net.Conn, data []byte) {
	size := len(data)
	size_bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(size_bytes, uint64(size))
	_, err := conn.Write(size_bytes)
	if err != nil {
		fmt.Println("Error in query")
		log.Fatal(err)
	}

	_, err = conn.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}

func Receive(c net.Conn) []byte {
	size_bytes := make([]byte, 8)
	_, err := io.ReadFull(c, size_bytes)
	if err != nil {
		log.Fatal(err)
	}

	size := binary.LittleEndian.Uint64(size_bytes)
	fmt.Printf("\nGot a size: %d", size)
	data := make([]byte, size)
	_, err = io.ReadFull(c, data)
	fmt.Println("Got data")
	return data
}
