package main

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
)

func main() {

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	// Add your image file
	f, err := os.Open("countries.csv")
	if err != nil {
		return
	}
	defer f.Close()
	fw, err := w.CreateFormFile("file", "countries.csv")
	if err != nil {
		return
	}
	if _, err = io.Copy(fw, f); err != nil {
		return
	}
	// Add the other fields
	if fw, err = w.CreateFormField("token"); err != nil {
		return
	}
	if _, err = fw.Write([]byte("0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")); err != nil {
		return
	}

	if fw, err = w.CreateFormField("path"); err != nil {
		return
	}
	if _, err = fw.Write([]byte("john")); err != nil {
		return
	}

	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	url_s := "http://127.0.0.1:3000/put_file"

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

	body := make([]byte, 200)

	fmt.Print("Made request\n\n")

	res.Body.Read(body)
	fmt.Print(string(body))

	/*
	       v := url.Values{}
	   	v.Set("token", "0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")
	   	v.Add("path", "/john")
	   	v.Add("file", "djfhnsdjfnksdj")
	   	v.Add("file_name", "TEsting")
	   	//reader := io.Reader("hi")
	   	resp, err := http.PostForm("http://127.0.0.1:3000/put_file", v)
	   	if err != nil {
	   		fmt.Print(err)
	   	}

	   	body := make([]byte, 200)

	   	resp.Body.Read(body)
	   	fmt.Print(string(body))
	*/
	v := url.Values{}
	v.Set("token", "0SKvdYWC6xR0wk9VKBtJDzn47Hpocbd1")
	v.Add("friend", "Jess")
	//reader := io.Reader("hi")
	resp, err := http.PostForm("http://127.0.0.1:3000/list_files", v)
	if err != nil {
		fmt.Print(err)
	}

	body = make([]byte, 200)

	resp.Body.Read(body)
	fmt.Print(string(body))
}
