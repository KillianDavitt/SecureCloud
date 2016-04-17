package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"github.com/KillianDavitt/SecureCloud/crypto"
	"github.com/KillianDavitt/SecureCloud/network"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
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
	s.query([]byte(id))
	encrypted_response := network.Receive(s.conn)
	response := crypto.Decrypt(encrypted_response, s.aes_key)
	fmt.Printf("\nId we got is: ", response)
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

	enc := crypto.Encrypt(bytes, key)
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
		if err != nil {
			log.Fatal(err)
		}
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
		log.Fatal(err)
	}

	// Check the response
	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("bad status: %s", res.Status)
		if err != nil {
			log.Fatal(err)
		}
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
		if err != nil {
			log.Fatal(err)
		}
	}

	body := make([]byte, res.ContentLength)
	res.Body.Read(body)

	key := s.get_key(s.current_ls[filename])

	fmt.Print(string(crypto.Decrypt(body, key)))

	fmt.Println("Writing to file")
	f.Write(body)
}

func (s *Server) ls() {
	s.query([]byte("ls"))
	encrypted_response := network.Receive(s.conn)
	response := crypto.Decrypt(encrypted_response, s.aes_key)

	response_string := string(response)
	files_list := make(map[string]string)
	files := strings.Split(response_string, "[")
	for i := 2; i < len(files)-1; i++ {
		files[i] = strings.Replace(files[i], "]", "", -1)
		files[i] = strings.Replace(files[i], " ", "", -1)
		files[i] = strings.Replace(files[i], "\"", "", -1)
		files[i] = strings.Replace(files[i], "\n", "", -1)

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

func (s *Server) decrypt_message(data []byte) []byte {
	return crypto.Decrypt(data, s.aes_key)
}

func (s *Server) encrypt_message(data []byte) []byte {
	return crypto.Encrypt(data, s.aes_key)
}

func (s *Server) query(data []byte) {
	ciphertext := s.encrypt_message(data)
	network.Send(s.conn, ciphertext)
}

func (s *Server) serverInit(ip string, priv rsa.PrivateKey, pub rsa.PublicKey, name string) {
	conn, err := net.Dial("tcp", ip+":2222")
	if err != nil {
		fmt.Println("\nApplication was unable to connect to the key server.\nPlease check the status of the key server or inform your key server manager of this error.\nAnotherpossible issue may be closed ports on the key servers connection.")
		log.Fatal(err)
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
	// Send the key onto server the Python after encrypting
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
