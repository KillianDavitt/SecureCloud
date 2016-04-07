package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"io"
	//"crypto/sha256"
	//"encoding/base64"
	"fmt"
	"net"
	"os"
	//"os/user"
	//	"strconv"
	//"crypto/eliptic
	"bytes"
	"crypto/x509"
	//"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net/http"
	//"path/filepath"
	"encoding/binary"
	"path"
	"runtime"
	"strings"
)

type Server struct {
	conn       net.Conn
	priv       rsa.PrivateKey
	pub        rsa.PublicKey
	server_pub rsa.PublicKey
	aes_key    []byte
	current_ls map[string]string
}

func (s *Server) get_key(id string) []byte {
	s.query([]byte("CK"))
	size_bytes := make([]uint8, 8)
	s.query([]byte(id))
	n, err := io.ReadFull(s.conn, size_bytes)
	size := binary.LittleEndian.Uint64(size_bytes)
	if err != nil {
		log.Fatal(err)
	}
	if n != 8 {
		log.Fatal("Size not equal to 1")
	}
	response := make([]uint8, size)
	_, err = io.ReadFull(s.conn, response)
	if err != nil {
		log.Fatal(err)
	}
	return response
}

func (s *Server) put(filename string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// Add your image file
	f, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Opened the file")
	defer f.Close()
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		log.Fatal(err)
	}
	var bytes []byte
	done := false
	for done != true {
		data := make([]byte, 1024)
		n, err := f.Read(data)
		if err != nil {
			log.Fatal(err)
		}
		if n < 1024 {
			done = true
		}
		bytes = append(bytes, data...)
	}
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}

	enc := s.encrypt_with_key(bytes, key)
	fw.Write(enc)
	//if _, err = io.Copy(fw, f); err != nil {
	//	log.Fatal(err)
	//}
	// Add the other fields
	if fw, err = w.CreateFormField("token"); err != nil {
		log.Fatal(err)
	}
	if _, err = fw.Write([]byte("0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")); err != nil {
		log.Fatal(err)
	}

	if fw, err = w.CreateFormField("path"); err != nil {
		log.Fatal(err)
	}
	if _, err = fw.Write([]byte("")); err != nil {
		return
	}

	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	url_s := "http://127.0.0.1:8000/put_file"

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", url_s, &b)
	if err != nil {
		fmt.Print(err)
	}

	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Print(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	}

	body := make([]byte, res.ContentLength)

	res.Body.Read(body)
	f.Write(body)

	s.query([]byte("HK"))
	s.query(key)
	s.query(body)
}

func (s *Server) rm(filename string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormField("id")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(s.current_ls[filename])
	if _, err := fw.Write([]byte(s.current_ls[filename])); err != nil {
		log.Fatal(err)
	}

	if fw, err = w.CreateFormField("token"); err != nil {
		log.Fatal(err)
	}

	if _, err := fw.Write([]byte("0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")); err != nil {
		log.Fatal(err)
	}
	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	url_s := "http://127.0.0.1:8000/rm_file"

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", url_s, &b)
	if err != nil {
		fmt.Print(err)
	}

	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Print(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	}

	body := make([]byte, res.ContentLength)
	fmt.Print("Made request\n\n")
	res.Body.Read(body)
	fmt.Print(string(body))

}

func (s *Server) get(filename string) {
	_, fname, _, _ := runtime.Caller(1)
	f, err := os.Create(path.Join(path.Dir(fname)+"/files", filename))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(path.Join(path.Dir(fname)+"/files", filename))
	//id := s
	fmt.Println(filename)
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// Add your image file

	//dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	//if err != nil {
	//		log.Fatal(err)
	//	}

	defer f.Close()
	fw, err := w.CreateFormFile("file", filename)
	if err != nil {
		log.Fatal(err)
	}
	if _, err = io.Copy(fw, f); err != nil {
		fmt.Println("Copy err")
		log.Fatal(err)
	}
	// Add the other fields
	if fw, err = w.CreateFormField("path"); err != nil {
		log.Fatal(err)
	}
	if _, err = fw.Write([]byte("")); err != nil {
		log.Fatal(err)
	}

	if fw, err = w.CreateFormField("id"); err != nil {
		log.Fatal(err)
	}
	fmt.Println(s.current_ls[filename])
	if _, err = fw.Write([]byte(s.current_ls[filename])); err != nil {
		log.Fatal(err)
	}

	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	url_s := "http://127.0.0.1:8000/get_file/" + s.current_ls[filename]

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("GET", url_s, &b)
	if err != nil {
		fmt.Print(err)
	}

	req.Header.Set("Content-Type", w.FormDataContentType())
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		fmt.Print(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
	}

	body := make([]byte, res.ContentLength)
	res.Body.Read(body)

	key := s.get_key(s.current_ls[filename])

	fmt.Print(string(decrypt_with_key(body, key)))

	/*done := false
	    for done != true {
			data := make([]byte, 1024)
			n, err := f.Read(data)
			if err != nil {
				log.Fatal(err)
			}
			if n < 1024 {
				done = true
			}
			fw.Write(s.encrypt(data))
		}
	*/
	fmt.Println("Writing to file")
	f.Write(body)
}

func (s *Server) ls() {
	s.query([]byte("ls"))
	size_bytes := make([]uint8, 8)
	n, err := io.ReadFull(s.conn, size_bytes)
	size := binary.LittleEndian.Uint64(size_bytes)

	if err != nil {
		log.Fatal(err)
	}
	if n != 8 {
		log.Fatal("Size not equal to 1")
	}
	response := make([]uint8, size)
	_, err = io.ReadFull(s.conn, response)
	if err != nil {
		log.Fatal(err)
	}

	response_string := string(response)
	files_list := make(map[string]string)
	files := strings.Split(response_string, "[")
	for i := 2; i < len(files)-1; i++ {
		files[i] = strings.Replace(files[i], "]", "", -1)
		files[i] = strings.Replace(files[i], " ", "", -1)
		files[i] = strings.Replace(files[i], "\"", "", -1)
		files[i] = strings.Replace(files[i], "\n", "", -1)

		//files_list[files[i%2]] = files[i%2+1]
		temp := strings.Split(files[i], ",")
		files_list[temp[1]] = temp[0]
	}

	for k, _ := range files_list {
		if k == "" || k == "\n" {
			delete(files_list, k)
		}
	}
	fmt.Println(response_string)
	for k, _ := range files_list {
		fmt.Println(k)
	}

	s.current_ls = files_list
}

func (s *Server) decrypt(data []byte) []byte {
	block, err := aes.NewCipher(s.aes_key)
	if err != nil {
		panic(err)
	}
	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)

	return data
}

func decrypt_with_key(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(data, data)

	return data
}

func (s *Server) encrypt_with_key(data []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}
	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)
	return ciphertext
}

func (s *Server) encrypt(data []byte) []byte {
	block, err := aes.NewCipher(s.aes_key)

	if err != nil {
		panic(err)
	}
	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)
	return ciphertext
}

func (s *Server) query(data []byte) {
	block, err := aes.NewCipher(s.aes_key)
	if err != nil {
		panic(err)
	}
	var iv = []byte{34, 35, 35, 57, 68, 4, 35, 36, 7, 8, 35, 23, 35, 86, 35, 23}

	cfb := cipher.NewCFBEncrypter(block, iv)
	ciphertext := make([]byte, len(data))
	cfb.XORKeyStream(ciphertext, data)
	_, err = s.conn.Write(ciphertext)
	if err != nil {
		log.Fatal(err)
	}
}

func (s *Server) serverInit(ip string, priv rsa.PrivateKey, pub rsa.PublicKey, name string) {
	conn, err := net.Dial("tcp", ip+":2222")
	if err != nil {
		// handle error
		fmt.Print(err)
	}
	s.conn = conn

	s.priv = priv
	s.pub = pub

	// Send over our pub
	fmt.Println("\nAbout to send our pub")
	pub_bytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(pub_bytes)
	if err != nil {
		log.Fatal(err)
	}
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	s.aes_key = key

	// Next we need to receive the servers pub
	server_pub_bytes := make([]uint8, 162)
	_, err = io.ReadFull(conn, server_pub_bytes)
	if err != nil {
		log.Fatal(err)
	}

	server_pub_interface, err := x509.ParsePKIXPublicKey(server_pub_bytes)
	if err != nil {
		log.Fatal(err)
	}

	var server_pub rsa.PublicKey
	server_pub = *server_pub_interface.(*rsa.PublicKey)
	fmt.Println("Successfully received a public key from the server")
	s.server_pub = server_pub
	// Send the key onto server th Python. after encrypting
	//EncryptPKCS1v15(rand io.Reader, pub *PublicKey, msg []byte) (out []byte, err error)
	fmt.Println("Attempting to encrypt and send aes key")
	rng := rand.Reader
	pubk := &server_pub
	encrypted_aes_key, err := rsa.EncryptPKCS1v15(rng, pubk, key)
	fmt.Println(len(encrypted_aes_key))
	_, err = conn.Write(encrypted_aes_key)
	if err != nil {
		log.Fatal(err)
	}
	// all the variables have been assigned to the server
	bname := make([]byte, 4)
	binary.LittleEndian.PutUint32(bname, uint32(len(name)))
	conn.Write(bname)
	conn.Write([]byte(name))
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func findServer() string {
	return "127.0.0.1"
}

/*func register(ip string, key rsa.PublicKey, ser *Server) bool {
	strE := strconv.Itoa(key.E)
	fmt.Fprintf(conn, strE+"\n")
	fmt.Fprintf(conn, key.N.String()+"\n\n")
	status, _ := bufio.NewReader(conn).ReadString('\n')
	fmt.Println(status)
	ser.conn = conn

	// Get servers public key store in server

	return true
}
*/
func main() {
	// First task, find a servera
	fmt.Println("Attempting to locate secure server...")
	ip := findServer()
	fmt.Println("Server found...")

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
	fmt.Println("Pick a username: ")
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
