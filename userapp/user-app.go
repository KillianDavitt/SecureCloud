package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

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

	var ser server
	server := &ser
	// Check for a local key
	// If yes, get key from server
	//usr, err := user.Current()
	privFile, err := os.Open("key.priv")
	registered := err == nil
	var pub rsa.PublicKey
	var priv rsa.PrivateKey
	if registered == true {
		// Read our local keys in
		// Including
		// Here, keys are on file and need to read them in
		fmt.Println("\nReading in client keys from disk.....")
		var privatePem []byte
		privatePem = make([]byte, 1024)
		_, err := privFile.Read(privatePem)
		if err != nil {
			log.Fatal(err)
		}
		//func ParsePKCS1PrivateKey(der []byte) (key *rsa.PrivateKey, err error)
		privateBytes, _ := pem.Decode(privatePem)
		privateKey, err := x509.ParsePKCS1PrivateKey(privateBytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		priv = *privateKey
		publicFile, err := os.Open("key.pub")

		var publicPem []byte
		publicPem = make([]byte, 1024)
		_, err = publicFile.Read(publicPem)
		if err != nil {
			log.Fatal(err)
		}
		//func ParsePKCS1PrivateKey(der []byte) (key *rsa.PrivateKey, err error)
		publicBytes, _ := pem.Decode(publicPem)
		publicKeyInterface, err := x509.ParsePKIXPublicKey(publicBytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		var publicKey rsa.PublicKey
		publicKey = *publicKeyInterface.(*rsa.PublicKey)
		pub = publicKey

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
