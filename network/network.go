package network

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// Send bytes to a given connection
func Send(conn net.Conn, data []byte) {
	size := len(data)
	sizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBytes, uint64(size))
	_, err := conn.Write(sizeBytes)
	if err != nil {
		fmt.Println("Error in query")
		log.Fatal(err)
	}

	_, err = conn.Write(data)
	if err != nil {
		log.Fatal(err)
	}
}

// Receive bytes from a give connection
func Receive(c net.Conn) []byte {
	sizeBytes := make([]byte, 8)
	_, err := io.ReadFull(c, sizeBytes)
	if err != nil {
		log.Fatal(err)
	}

	size := binary.LittleEndian.Uint64(sizeBytes)
	fmt.Printf("\nGot a size: %d", size)
	data := make([]byte, size)
	_, err = io.ReadFull(c, data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Got data")
	return data
}
