package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"time"
)

func CreateSignature(pk string, secret string, req *http.Request) (string, error) {
	timestamp := time.Now().UTC().Format(http.TimeFormat)
	method := req.Method
	path := "/" + path.Base(req.URL.Path)
	if req.URL.RawQuery != "" {
		path = path + "?" + req.URL.RawQuery
	}
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	hasher := sha256.New()
	hasher.Write(body)
	content_hash := base64.StdEncoding.EncodeToString(hasher.Sum(nil))

	string_to_sign := fmt.Sprintf("%s\n%s\n%s\n%s", method, path, timestamp, content_hash)

	hasher_sign := hmac.New(sha256.New, []byte(secret))
	hasher_sign.Write([]byte(string_to_sign))

	signature := base64.StdEncoding.EncodeToString(hasher_sign.Sum(nil))

	return signature, nil
}

func main() {
	data := []byte("requestBody")
	request, _ := http.NewRequest("method", "url", bytes.NewBuffer(data))
	signature, err := CreateSignature("appKey", "secret", request)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(signature)
}
