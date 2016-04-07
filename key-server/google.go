package main

import (
	"crypto/rsa"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v2"
	"io"
	"io/ioutil"
	"log"
	//"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	//"strconv"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	//"encoding/base64"
	"encoding/pem"
	"time"
)

func getClient(ctx context.Context, config *oauth2.Config) *http.Client {
	cacheFile, err := tokenCacheFile()
	if err != nil {
		log.Fatalf("Unable to get path to cached credential file. %v", err)
	}
	tok, err := tokenFromFile(cacheFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(cacheFile, tok)
	}
	return config.Client(ctx, tok)
}

// getTokenFromWeb uses Config to request a Token.
// It returns the retrieved Token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// tokenCacheFile generates credential file path/filename.
// It returns the generated credential path/filename.
func tokenCacheFile() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	tokenCacheDir := filepath.Join(usr.HomeDir, "/.config/securecloud")
	os.MkdirAll(tokenCacheDir, 0700)
	return filepath.Join(tokenCacheDir,
		url.QueryEscape("credentials.json")), err
}

// tokenFromFile retrieves a Token from a given file path.
// It returns the retrieved Token and any read error encountered.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	t := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(t)
	defer f.Close()
	return t, err
}

// saveToken uses a file path to create a file and store the
// token in it.
func saveToken(file string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", file)
	f, err := os.Create(file)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}

type Server struct {
	pub    rsa.PublicKey
	priv   rsa.PrivateKey
	client http.Client
}

type Client struct {
	pub     rsa.PublicKey
	aes_key []byte
}

func main() {
	// Assosiate with a gdrive,
	// We need a username and pass unless its stored already

	//Check if we have credentials
	usr, err := user.Current()
	if err != nil {
		return
	}
	var s Server
	_, err = os.Open(usr.HomeDir + "/.config/securecloud/credentials.json")
	if err != nil {
		ctx := context.Background()
		fmt.Println("Making new creds")
		b, err := ioutil.ReadFile(usr.HomeDir + "/.config/securecloud/client_secret.json")
		if err != nil {
			log.Fatalf("Unable to read client secret file: %v", err)
		}

		// If modifying these scopes, delete your previously saved credentials
		// at ~/.credentials/drive-go-quickstart.json
		config, err := google.ConfigFromJSON(b, drive.DriveScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
		}
		client := getClient(ctx, config)

		s.client = *client
		//if s.srv == nil {
		//	fmt.Print("yep,its nil")
		//}
		if err != nil {
			log.Fatalf("Unable to retrieve drive Client %v", err)
		}

	}

	//if s.srv == nil {
	//	fmt.Println("Feckin nil")
	//}
	server := &s
	clients := make(map[string]Client)

	//if server.srv == nil {
	//	fmt.Println("yepit sdef nil")
	//}
	// Check for a local key
	// If yes, get key from server
	//usr, err := user.Current()
	_, err = os.Open("/key.priv")
	registered := err == nil
	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey
	if registered == true {
		// Read our local keys in
		// Including
	} else {
		// If we are not registered, we need to create keys and save them to disk
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

		fmt.Print("About to write")
		ioutil.WriteFile("key.pub", pubBytes, 0644)

		pemdata := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)

		fmt.Print("About to write")
		ioutil.WriteFile("key.priv", pemdata, 0644)

	}
	// Keys are now in server datastructure

	// Now, we have a gdrive session
	acceptSessions(server, clients)

	//go acceptCommands()

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

	handle_commands(conn, client, s)

	fmt.Println("Session Ended....")
}
func list(s *Server) string {
	client := s.client
	srv, err := drive.New(&client)
	if err != nil {
		log.Fatal(err)
	}
	r, err := srv.Files.List().MaxResults(200).Fields("items/title").MaxResults(40).Do() //.Fields("nextPageToken, files(id, name)").Do()
	time.Sleep(2)
	if err != nil {
		log.Fatalf("Unable to retrieve files.", err)
	}
	var files string
	items := r.Items
	for i := 0; i < len(items); i++ {
		files += items[i].Title + "\n"
	}
	return files
}

func handle_commands(conn net.Conn, client Client, s *Server) {
	// Listen for "ls" or "put" or anything like that
	for {
		data := make([]byte, 2)
		_, err := io.ReadFull(conn, data)
		if err != nil {
			log.Fatal(err)
		}
		// Have data, now decrypt with aes
		plain := string(decrypt(data, client.aes_key))
		fmt.Println(plain)
		if plain == "ls" {
			response := []byte(list(s))
			size := make([]byte, 4)
			binary.LittleEndian.PutUint32(size, uint32(len(response)))

			_, _ = conn.Write(size)
			_, _ = conn.Write([]byte(list(s)))
		}
	}
}

func decrypt(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	//ciphertext, err := base64.StdEncoding.DecodeString(string(data))
	//if err != nil {
	//	log.Fatal(err)
	//}
	ciphertext := data
	cfb := cipher.NewCFBEncrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	cfb.XORKeyStream(plaintext, ciphertext)
	return plaintext
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
