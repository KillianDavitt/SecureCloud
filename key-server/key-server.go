package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"github.com/KillianDavitt/SecureCloud/crypto"
	"github.com/KillianDavitt/SecureCloud/network"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
)

type server struct {
	pub    rsa.PublicKey
	priv   rsa.PrivateKey
	client http.Client
	keys   map[string][]byte
	db     *sql.DB
}

func (c *client) initis() bool { return c.init }

type client struct {
	init     bool
	username string
	pub      rsa.PublicKey
	aesKey   []byte
	trusted  bool
}

func (s *server) putKey(conn net.Conn, c client) {
	encryptedKey := network.Receive(conn)
	key := crypto.Decrypt(encryptedKey, c.aesKey)
	id := make([]byte, 10)
	_, err := io.ReadFull(conn, id)
	if err != nil {
		log.Fatal(err)
	}
	id = crypto.Decrypt(id, c.aesKey)
	fmt.Println(string(id))
	s.keys[string(id)] = key
	fmt.Println(s.keys[string(id)])
}

func (s *server) getKey(conn net.Conn, c client) []byte {
	encryptedId := network.Receive(conn)
	id := crypto.Decrypt(encryptedId, c.aesKey)
	return s.keys[string(id)]
}

func main() {

	db, err := sql.Open("sqlite3", "./securecloud.db")
	if err != nil {
		log.Fatal(err)
	}

	clients := make(map[string]client)

	rows, err := db.Query("SELECT username,pub_key,trusted FROM users")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Loading Users......")
	for rows.Next() {
		var c client
		var username string
		var pubKeyBytes []byte
		var trusted bool
		err = rows.Scan(&username, &pubKeyBytes, &trusted)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print("\nLoaded user: ")
		fmt.Print(username)
		//func parsePKCS1PrivateKey(der []byte) (key *rsa.privateKey, err error)
		pubKeyInterface, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			log.Fatal(err)
		}
		var pubKey rsa.PublicKey
		pubKey = *pubKeyInterface.(*rsa.PublicKey)

		c.pub = pubKey
		c.init = true
		c.username = username
		c.trusted = trusted
		mapIndex := pubKey.N.String()

		clients[mapIndex] = c

	}

	var s server
	server := &s

	// Make the map for aes keys, one for each file
	keys := make(map[string][]byte)
	server.keys = keys
	server.db = db

	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey

	privFile, err := os.Open("key.priv")
	if err != nil {
		// In here means we have no key and need to gen one
		// we need to create keys and save them to disk
		rng := rand.Reader
		fmt.Println("Generating RSA Key....")
		priv, _ = rsa.GenerateKey(rng, 1024)
		s.priv = *priv

		pub = &priv.PublicKey
		s.pub = *pub

		// Now, write keys to disk
		pubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			// do something about it
		}

		pubBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubASN1,
		})

		fmt.Print("\nWriting public key to disk....")
		ioutil.WriteFile("key.pub", pubBytes, 0644)
		fmt.Print("...Success!\n")
		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)

		fmt.Print("Writing private key to disk....")
		ioutil.WriteFile("key.priv", pemdata, 0644)
		fmt.Print("...Success!\n")
	} else {
		// Here, keys are on file and need to read them in
		fmt.Println("\nReading in server keys from disk.....")
		var privatePem []byte
		privatePem = make([]byte, 1024)
		_, err := privFile.Read(privatePem)
		if err != nil {
			log.Fatal(err)
		}
		//func parsePKCS1PrivateKey(der []byte) (key *rsa.privateKey, err error)
		privateBytes, _ := pem.Decode(privatePem)
		privKey, err := x509.ParsePKCS1PrivateKey(privateBytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		s.priv = *privKey
		pubFile, err := os.Open("key.pub")

		var publicPem []byte
		publicPem = make([]byte, 1024)
		_, err = pubFile.Read(publicPem)
		if err != nil {
			log.Fatal(err)
		}
		//func parsePKCS1PrivateKey(der []byte) (key *rsa.privateKey, err error)
		publicBytes, _ := pem.Decode(publicPem)
		pubKeyInterface, err := x509.ParsePKIXPublicKey(publicBytes.Bytes)
		if err != nil {
			fmt.Println(err)
		}
		var pubKey rsa.PublicKey
		pubKey = *pubKeyInterface.(*rsa.PublicKey)
		s.pub = pubKey

	}
	fmt.Println("Assigned All vars")
	// Keys are now in server datastructure

	acceptSessions(server, clients)

	fmt.Println(" ")
	////////////////done := false
	/*for done != true {
		fmt.Print("secureCloud>")
		var command string
		//fmt.Scanf("%s", &command)
		fmt.Println(command)
	}*/

}

func recievePublicKey(conn net.Conn) (rsa.PublicKey, []byte) {
	clientPubBytes := make([]uint8, 162)
	_, err := io.ReadFull(conn, clientPubBytes)
	if err != nil {
		log.Fatal(err)
	}
	clientPubInterface, err := x509.ParsePKIXPublicKey(clientPubBytes)
	if err != nil {
		log.Fatal(err)
	}
	var clientPub rsa.PublicKey
	clientPub = *clientPubInterface.(*rsa.PublicKey)
	fmt.Println("Sucessfully received a public key from this user...")
	return clientPub, clientPubBytes
}

func session(s *server, conn net.Conn, c map[string]client) {
	ip := conn.RemoteAddr().String()
	fmt.Println("Received connection from: " + ip)

	// Send our public key

	// Receive their public key
	clientPub, clientPubBytes := recievePublicKey(conn)
	// We have the pub, do we know this person?
	mapIndex := clientPub.N.String()
	client := c[mapIndex]

	serverPubBytes, err := x509.MarshalPKIXPublicKey(&s.pub)
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.Write(serverPubBytes)
	if err != nil {
		log.Fatal(err)
	}
	// Negotiate an aes key
	// Receive a blob, decrypt it with our priv key
	//func readAtLeast(r Reader, buf []byte, min int) (n int, err error)
	encryptedAesKey := make([]byte, 128)
	_, err = io.ReadFull(conn, encryptedAesKey)
	if err != nil {
		log.Fatal(err)
	}
	//decryptPKCS1v15(rand io.Reader, priv *privateKey, ciphertext []byte) (out []byte, err error)
	rng := rand.Reader
	aesKey, err := rsa.DecryptPKCS1v15(rng, &s.priv, encryptedAesKey)
	if err != nil {
		log.Fatal(err)
	}
	client.aesKey = aesKey

	sizeBytes := make([]uint8, 4)
	n, err := io.ReadFull(conn, sizeBytes)
	size := binary.LittleEndian.Uint32(sizeBytes)
	if err != nil {
		log.Fatal(err)
	}
	if n != 4 {
		log.Fatal("Size not equal to 1")
	}
	response := make([]uint8, size)
	_, err = io.ReadFull(conn, response)
	if err != nil {
		log.Fatal(err)
	}
	name := string(response)

	negotiateTrust(conn, s, clientPubBytes, client, name)
}

func negotiateTrust(conn net.Conn, s *server, clientPubBytes []byte, client client, name string) {

	trusted := false
	if client.initis() {
		fmt.Printf("\nWe've seen this user before: %s", client.username)
		if client.trusted {
			fmt.Println("This user is trusted")
			trusted = true
		}
	}

	var answer string
	fmt.Println(trusted)
	if !trusted {
		answer = ""
		fmt.Println(name + " has connected, press y to allow access to the cloud..\n")
		fmt.Scanf("%s", &answer)
		fmt.Println(answer)
	}
	fmt.Println(answer)
	if answer == "y" || trusted {
		fmt.Println("You have allowed this user")
		trusted = true
		var stmt *sql.Stmt
		var err error
		if !client.trusted {
			stmt, err = s.db.Prepare("INSERT INTO users(username, pubKey, trusted) values(?,?, ?);")
			if err != nil {
				log.Fatal(err)
			}
			res, err := stmt.Exec(name, clientPubBytes, trusted)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(res)

		}
		handleCommands(conn, client, s)
	}
	fmt.Println("Session Ended....")

}

func list(s *server) string {
	v := url.Values{}
	v.Set("token", "0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")
	//reader := io.Reader("hi")
	resp, err := http.PostForm("http://127.0.0.1:8000/listFiles", v)
	if err != nil {
		fmt.Print("There was an error connecting to the server, please ensure the cloud server is turned on")
		log.Fatal(err)
	}

	body := make([]byte, resp.ContentLength)
	resp.Body.Read(body)
	return (string(body))

}

func handleCommands(conn net.Conn, client client, s *server) {
	// Listen for "ls" or "put" or anything like that
	fmt.Println("Handling commands")
	for {
		fmt.Println("About to recv command")

		encryptedData := network.Receive(conn)

		fmt.Println("Received command, about to decrypt")
		// Have data, now decrypt with aes
		plain := string(crypto.Decrypt(encryptedData, client.aesKey))
		fmt.Println("Got a plain: ")
		fmt.Println(plain)
		if plain == "ls" {
			response := []byte(list(s))
			encryptedResponse := crypto.Encrypt(response, client.aesKey)
			network.Send(conn, encryptedResponse)
		} else if plain == "HK" {
			fmt.Println("Attempting to register a new key")
			s.putKey(conn, client) //)

		} else if plain == "CK" {
			fmt.Println("Attempting to get a key for a user")
			response := []byte(s.getKey(conn, client))
			encryptedResponse := crypto.Encrypt(response, client.aesKey)
			network.Send(conn, encryptedResponse)
		}
	}
}

func acceptSessions(server *server, clients map[string]client) {
	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		fmt.Print("oooo")
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Printf("err")
		}
		go session(server, conn, clients)
		fmt.Print("Going around")
	}
}

func (c *client) send(conn net.Conn, data []byte) {
	ciphertext := crypto.Encrypt(data, c.aesKey)
	size := len(ciphertext)
	sizeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(sizeBytes, uint64(size))
	_, err := conn.Write(sizeBytes)
	if err != nil {
		fmt.Println("Error in query")
		log.Fatal(err)
	}

	_, err = conn.Write(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
}

func receive(c net.Conn) []byte {
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
