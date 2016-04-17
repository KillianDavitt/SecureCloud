package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func testDecrypt(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
	}

	originalPlaintext := "Hi, this is a test of the encryption/decryption"

	ciphertext := Encrypt([]byte(originalPlaintext), key)

	plaintext := Decrypt(ciphertext, key)

	if string(plaintext) != originalPlaintext {
		t.Error("Decrypted text does not match original plaintext")
	}

	otherKey := make([]byte, 32)
	_, err = rand.Read(otherKey)
	if err != nil {
		fmt.Println(err)
	}

	incorrectPlaintext := Decrypt(ciphertext, otherKey)

	if string(incorrectPlaintext) == originalPlaintext {
		t.Error("Different keys produced correct plaintext, this is a severe problem")
	}

}
