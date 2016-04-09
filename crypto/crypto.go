package crypto

import (
	"fmt"
)

func decrypt([]byte data, []byte key) []byte {
    block, err := aes.NewCipher(s.aes_key)
	if err != nil {
		fmt.Println("There was an error during decryption. Program will now terminate")
		log.Fatal(err)
	}

	// Extract the iv from the end of ciphertext
	iv := data[len(data)-32:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data[:len(data)-32], data)

	return data
}

func encrypt([]byte data, []byte key) []byte {
    block, err := aes.NewCipher(s.aes_key)

	if err != nil {
		panic(err)
	}

	var iv []byte
	iv = make([]byte, 16)
	_, err = rand.Read(iv)

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)

	// Append iv to the ciphertext
	return append(ciphertext, iv...)
}
