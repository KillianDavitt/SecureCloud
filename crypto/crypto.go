package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
)

const blockSize int = 16

// Decrypt function takes a key and encrypted bytes and returns decrypted data
func Decrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There was an error during decryption. Program will now terminate")
		log.Fatal(err)
	}

	// Extract the iv from the end of ciphertext
	iv := data[len(data)-blockSize:]
	ciphertext := data[:len(data)-blockSize]

	plaintext := make([]byte, len(ciphertext))

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(plaintext, ciphertext)
	return plaintext
}

// Encrypt function takes a key and data and returns encrypted data
func Encrypt(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There was an error during decryption, the program will now terminate")
		log.Fatal(err)
	}

	var iv []byte
	iv = make([]byte, blockSize)
	_, err = rand.Read(iv)
	if err != nil {
		log.Fatal(err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(plaintext))
	cfb.XORKeyStream(ciphertext, plaintext)

	// Append iv to the ciphertext
	return append(ciphertext, iv...)
}
