package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
)

const BLOCK_SIZE int = 16

func Decrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There was an error during decryption. Program will now terminate")
		log.Fatal(err)
	}

	// Extract the iv from the end of ciphertext
	iv := data[len(data)-BLOCK_SIZE:]
	ciphertext := data[:len(data)-BLOCK_SIZE]

	plaintext := make([]byte, len(ciphertext))

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(plaintext, ciphertext)
	return plaintext
}

func Encrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There was an error during decryption, the program will now terminate")
		log.Fatal(err)
	}

	var iv []byte
	iv = make([]byte, BLOCK_SIZE)
	_, err = rand.Read(iv)

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	// Append iv to the ciphertext
	return append(ciphertext, iv...)
}
