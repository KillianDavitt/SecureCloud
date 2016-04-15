package crypto

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func test_decrypt(t *testing.T) {

	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		fmt.Println(err)
	}

	original_plaintext := "Hi, this is a test of the encryption/decryption"

	ciphertext := Encrypt([]byte(original_plaintext), key)

	plaintext := Decrypt(ciphertext, key)

	if string(plaintext) != original_plaintext {
		t.Error("Decrypted text does not match original plaintext")
	}

	other_key := make([]byte, 32)
	_, err = rand.Read(other_key)
	if err != nil {
		fmt.Println(err)
	}

	incorrect_plaintext := Decrypt(ciphertext, other_key)

	if string(incorrect_plaintext) == original_plaintext {
		t.Error("Different keys produced correct plaintext, this is a severe problem")
	}

}
