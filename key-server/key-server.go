package main

import (
	"../crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
)

type Server struct {
	pub    rsa.PublicKey
	priv   rsa.PrivateKey
	client http.Client
	keys   map[string][]byte
	db     *sql.DB
}

func (c *Client) initis() bool { return c.init }

type Client struct {
	init     bool
	username string
	pub      rsa.PublicKey
	aes_key  []byte
	trusted  bool
}

func (s *Server) put_key(conn net.Conn, c Client) {
	key := make([]byte, 32)
	_, err := io.ReadFull(conn, key)
	if err != nil {
		log.Fatal(err)
	}
	key = crypto.Decrypt(key, c.aes_key)
	id := make([]byte, 10)
	_, err = io.ReadFull(conn, id)
	if err != nil {
		log.Fatal(err)
	}
	id = crypto.Decrypt(id, c.aes_key)
	fmt.Println(string(id))
	s.keys[string(id)] = key
	fmt.Println(s.keys[string(id)])
}

func (s *Server) get_key(conn net.Conn, c Client) []byte {
	id := make([]byte, 10)
	_, err := io.ReadFull(conn, id)
	if err != nil {
		log.Fatal(err)
	}
	id = crypto.Decrypt(id, c.aes_key)
	return s.keys[string(id)]
}

func main() {

	db, err := sql.Open("sqlite3", "./securecloud.db")
	if err != nil {
		log.Fatal(err)
	}

	clients := make(map[string]Client)

	rows, err := db.Query("SELECT username,pub_key,trusted FROM users")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Loading Users......")
	for rows.Next() {
		var c Client
		var username string
		var pub_key_bytes []byte
		var trusted bool
		err = rows.Scan(&username, &pub_key_bytes, &trusted)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print("\nLoaded user: ")
		fmt.Print(username)
		//func ParsePKCS1PrivateKey(der []byte) (key *rsa.PrivateKey, err error)
		pub_key_interface, err := x509.ParsePKIXPublicKey(pub_key_bytes)
		if err != nil {
			log.Fatal(err)
		}
		var pub_key rsa.PublicKey
		pub_key = *pub_key_interface.(*rsa.PublicKey)

		c.pub = pub_key
		c.init = true
		c.username = username
		c.trusted = trusted
		map_index := pub_key.N.String()

		clients[map_index] = c

	}

	var s Server
	server := &s

	// Make the map for aes keys, one for each file
	keys := make(map[string][]byte)
	server.keys = keys
	server.db = db

	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey

	priv_file, err := os.Open("key.priv")
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
		PubASN1, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			// do something about it
		}

		pubBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: PubASN1,
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
		s.priv = *priv_key
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
		s.pub = pub_key

	}
	fmt.Println("Assigned All vars")
	// Keys are now in server datastructure

	acceptSessions(server, clients)

	fmt.Println("\n")
	////////////////done := false
	/*for done != true {
		fmt.Print("SecureCloud>")
		var command string
		//fmt.Scanf("%s", &command)
		fmt.Println(command)
	}*/

}

func session(s *Server, conn net.Conn, c map[string]Client) {
	ip := conn.RemoteAddr().String()
	fmt.Println("Received connection from: " + ip)

	// Send our public key

	// Receive their public key
	client_pub_bytes := make([]uint8, 162)
	_, err := io.ReadFull(conn, client_pub_bytes)
	if err != nil {
		log.Fatal(err)
	}
	client_pub_interface, err := x509.ParsePKIXPublicKey(client_pub_bytes)
	if err != nil {
		log.Fatal(err)
	}
	var client_pub rsa.PublicKey
	client_pub = *client_pub_interface.(*rsa.PublicKey)
	fmt.Println("Sucessfully received a public key from this user...")
	// We have the pub, do we know this person?
	map_index := client_pub.N.String()
	client := c[map_index]

	trusted := false
	if client.initis() {
		fmt.Printf("\nWe've seen this user before: %s", client.username)
		if client.trusted {
			fmt.Println("This user is trusted")
			trusted = true
		}
	}
	server_pub_bytes, err := x509.MarshalPKIXPublicKey(&s.pub)
	if err != nil {
		log.Fatal(err)
	}

	_, err = conn.Write(server_pub_bytes)
	if err != nil {
		log.Fatal(err)
	}
	// Negotiate an aes key
	// Receive a blob, decrypt it with our priv key
	//func ReadAtLeast(r Reader, buf []byte, min int) (n int, err error)
	encrypted_aes_key := make([]byte, 128)
	_, err = io.ReadFull(conn, encrypted_aes_key)
	if err != nil {
		log.Fatal(err)
	}
	//DecryptPKCS1v15(rand io.Reader, priv *PrivateKey, ciphertext []byte) (out []byte, err error)
	rng := rand.Reader
	aes_key, err := rsa.DecryptPKCS1v15(rng, &s.priv, encrypted_aes_key)
	if err != nil {
		log.Fatal(err)
	}
	client.aes_key = aes_key

	size_bytes := make([]uint8, 4)
	n, err := io.ReadFull(conn, size_bytes)
	size := binary.LittleEndian.Uint32(size_bytes)
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
		if !client.trusted {
			stmt, err = s.db.Prepare("INSERT INTO users(username, pub_key, trusted) values(?,?, ?);")
			if err != nil {
				log.Fatal(err)
			}
			res, err := stmt.Exec(name, client_pub_bytes, trusted)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(res)

		}
		handle_commands(conn, client, s)
	}
	fmt.Println("Session Ended....")
}
func list(s *Server) string {
	v := url.Values{}
	v.Set("token", "0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")
	//reader := io.Reader("hi")
	resp, err := http.PostForm("http://127.0.0.1:8000/list_files", v)
	if err != nil {
		fmt.Print("There was an error connecting to the server, please ensure the cloud server is turned on")
		log.Fatal(err)
	}

	body := make([]byte, resp.ContentLength)
	resp.Body.Read(body)
	return (string(body))

}

func handle_commands(conn net.Conn, client Client, s *Server) {
	// Listen for "ls" or "put" or anything like that
	fmt.Println("Handling commands")
	for {
		fmt.Println("About to recv command")
		data := receive(conn)
		fmt.Println("Received command, about to decrypt")
		// Have data, now decrypt with aes
		plain := string(crypto.Decrypt(data, client.aes_key))
		fmt.Println("Got a plain: ")
		fmt.Println(plain)
		if plain == "ls" {
			response := []byte(list(s))
			size := make([]byte, 8)
			binary.LittleEndian.PutUint32(size, uint32(len(response)))
			_, _ = conn.Write(size)
			_, _ = conn.Write(response)
		} else if plain == "HK" {
			fmt.Println("Attempting to register a new key")
			//response := []byte(
			s.put_key(conn, client) //)
			/*size := make([]byte, 8)
			binary.LittleEndian.PutUint32(size, uint32(len(response)))
			_, _ = conn.Write(size)
			_, _ = conn.Write(response)*/

		} else if plain == "CK" {
			fmt.Println("Attempting to get a key for a user")
			response := []byte(s.get_key(conn, client))
			size := make([]byte, 8)
			binary.LittleEndian.PutUint32(size, uint32(len(response)))
			fmt.Println(len(response))
			_, _ = conn.Write(size)
			_, _ = conn.Write(response)

		}
	}
}

func acceptSessions(server *Server, clients map[string]Client) {
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

func receive(c net.Conn) []byte {
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
