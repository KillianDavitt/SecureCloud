package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// encrypt, allowing a specified key
func encrypt_with_key(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There has been an encryption error. Program will now terminate")
		log.Fatal(err)
	}

	var iv []byte
	_, err = rand.Read(iv)
	if err != nil {
		log.Fatal(err)
	}
	iv = make([]byte, 32)

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)

	// Append the iv to the ciphertext
	return append(ciphertext, iv...)
}

// decrypt, allowing a specified key
func decrypt_with_key(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("There has been a decryption error. program will now terminate")
		log.Fatal(err)
	}

	// Extract iv from end of ciphertext
	iv := data[len(data)-32:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data[:len(data)-32], data)

	return data
}

func findServer() string {
	return "127.0.0.1"
}

func main() {
	f, err := os.OpenFile("userapp.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	// First task, find a servera
	fmt.Println("Loading key server address...")
	ip := findServer()
	fmt.Println("Address found...")

	var ser Server
	server := &ser
	// Check for a local key
	// If yes, get key from server
	//usr, err := user.Current()
	priv_file, err := os.Open("key.priv")
	registered := err == nil
	var pub rsa.PublicKey
	var priv rsa.PrivateKey
	if registered == true {
		// Read our local keys in
		// Including
		// Here, keys are on file and need to read them in
		fmt.Println("\nReading in client keys from disk.....")
		var private_pem []byte
		private_pem = make([]byte, 1024)
		_, err := priv_file.Read(private_pem)
		if err != nil {
			log.Fatal(err)
		}
		//func ParsePKCS1PrivateKey(der []byte) (key *rsa.PrivateKey, err error)
		private_bytes, _ := pem.Decode(private_pem)
		priv_key, err := x509.ParsePKCS1PrivateKey(private_bytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		priv = *priv_key
		pub_file, err := os.Open("key.pub")

		var public_pem []byte
		public_pem = make([]byte, 1024)
		_, err = pub_file.Read(public_pem)
		if err != nil {
			log.Fatal(err)
		}
		//func ParsePKCS1PrivateKey(der []byte) (key *rsa.PrivateKey, err error)
		public_bytes, _ := pem.Decode(public_pem)
		pub_key_interface, err := x509.ParsePKIXPublicKey(public_bytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		var pub_key rsa.PublicKey
		pub_key = *pub_key_interface.(*rsa.PublicKey)
		pub = pub_key

	} else {
		// If we are not registered, we need to create keys and save them to disk
		rng := rand.Reader
		fmt.Println("Generating RSA Key....")
		priv, _ := rsa.GenerateKey(rng, 1024)

		pub = priv.PublicKey
		//ret := register(ip, pub, server)
		//if ret == false {
		//	log.Fatal("Fail")
		//}

		PubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			// do something about it
		}

		pubBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: PubASN1,
		})

		fmt.Print("Writing public key to disk")
		ioutil.WriteFile("key.pub", pubBytes, 0644)

		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)

		fmt.Print("Writing Private key to disk")
		ioutil.WriteFile("key.priv", pemdata, 0644)

	}

	name := ""
	fmt.Println("\nPick a username: ")
	fmt.Scanf("%s", &name)

	// At this point we have an rsa key
	server.serverInit(ip, priv, pub, name)
	// Now, we just ask the user what they want

	x := []string{"help", "get", "put", "ls", "rm"}
	input := ""
	for {
		fmt.Print("\nSecureCloud>")
		fmt.Scanf("%s", &input)

		if input == x[0] {
			help()
		} else if input == x[1] {
			filename := ""
			fmt.Scanf("%s", &filename)
			ser.get(filename)
		} else if input == x[2] {
			filename := ""
			fmt.Scanf("%s", &filename)
			ser.put(filename)
		} else if input == x[3] {
			ser.ls()
		} else if input == x[4] {
			filename := ""
			fmt.Scanf("%s", &filename)
			ser.rm(filename)
		} else {
			fmt.Printf("\nInvalid option: %s \n Valid options are:\n", input)
			help()
		}
	}
}

func help() {
	fmt.Printf("get <file>\nput <file>\n")
}
