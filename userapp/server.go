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

type server struct {
	conn      net.Conn
	priv      rsa.PrivateKey
	pub       rsa.PublicKey
	serverPub rsa.PublicKey
	aesKey    []byte
	currentLs map[string]string
}

func (s *server) getKey(id string) []byte {
	s.query([]byte("CK"))
	s.query([]byte(id))
	encryptedResponse := network.Receive(s.conn)
	response := crypto.Decrypt(encryptedResponse, s.aesKey)
	fmt.Printf("\nId we got is: %s", response)
	return response
}

func (s *server) put(filename string) {
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

	urlS := "http://127.0.0.1:8000/put_file"

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", urlS, &b)
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

func (s *server) rm(filename string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormField("id")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(s.currentLs[filename])
	if _, err := fw.Write([]byte(s.currentLs[filename])); err != nil {
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

	urlS := "http://127.0.0.1:8000/rm_file"

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", urlS, &b)
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

func (s *server) get(filename string) {
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
	fmt.Println(s.currentLs[filename])
	if _, err = fw.Write([]byte(s.currentLs[filename])); err != nil {
		log.Fatal(err)
	}

	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	urlS := "http://127.0.0.1:8000/get_file/" + s.currentLs[filename]

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("GET", urlS, &b)
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

	key := s.getKey(s.currentLs[filename])

	fmt.Print(string(crypto.Decrypt(body, key)))

	fmt.Println("Writing to file")
	f.Write(body)
}

func (s *server) ls() {
	s.query([]byte("ls"))
	encryptedResponse := network.Receive(s.conn)
	response := crypto.Decrypt(encryptedResponse, s.aesKey)

	responseString := string(response)
	filesList := make(map[string]string)
	files := strings.Split(responseString, "[")
	for i := 2; i < len(files)-1; i++ {
		files[i] = strings.Replace(files[i], "]", "", -1)
		files[i] = strings.Replace(files[i], " ", "", -1)
		files[i] = strings.Replace(files[i], "\"", "", -1)
		files[i] = strings.Replace(files[i], "\n", "", -1)

		temp := strings.Split(files[i], ",")
		filesList[temp[1]] = temp[0]
	}

	for k := range filesList {
		if k == "" || k == "\n" {
			delete(filesList, k)
		}
	}
	fmt.Println(responseString)
	for k := range filesList {
		fmt.Println(k)
	}

	s.currentLs = filesList
}

func (s *server) decryptMessage(data []byte) []byte {
	return crypto.Decrypt(data, s.aesKey)
}

func (s *server) encryptMessage(data []byte) []byte {
	return crypto.Encrypt(data, s.aesKey)
}

func (s *server) query(data []byte) {
	ciphertext := s.encryptMessage(data)
	network.Send(s.conn, ciphertext)
}

func (s *server) serverInit(ip string, priv rsa.PrivateKey, pub rsa.PublicKey, name string) {
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
	publicBytes, err := x509.MarshalPKIXPublicKey(&pub)
	if err != nil {
		log.Fatal(err)
	}
	_, err = conn.Write(publicBytes)
	if err != nil {
		log.Fatal(err)
	}
	key := make([]byte, 32)

	_, err = rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	s.aesKey = key

	// Next we need to receive the servers pub
	serverPublicBytes := make([]uint8, 162)
	_, err = io.ReadFull(conn, serverPublicBytes)
	if err != nil {
		log.Fatal(err)
	}

	serverPublicInterface, err := x509.ParsePKIXPublicKey(serverPublicBytes)
	if err != nil {
		log.Fatal(err)
	}

	var serverPub rsa.PublicKey
	serverPub = *serverPublicInterface.(*rsa.PublicKey)
	fmt.Println("Successfully received a public key from the server")
	s.serverPub = serverPub
	// Send the key onto server the Python after encrypting
	fmt.Println("Attempting to encrypt and send aes key")
	rng := rand.Reader
	pubk := &serverPub
	encryptedAesKey, err := rsa.EncryptPKCS1v15(rng, pubk, key)
	fmt.Println(len(encryptedAesKey))
	_, err = conn.Write(encryptedAesKey)
	if err != nil {
		log.Fatal(err)
	}
	// all the variables have been assigned to the server
	bname := make([]byte, 4)
	binary.LittleEndian.PutUint32(bname, uint32(len(name)))
	conn.Write(bname)
	conn.Write([]byte(name))
}
