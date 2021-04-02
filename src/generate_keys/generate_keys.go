package main

import (
	"crypto/dsa"
	"crypto/rand"
	"encoding/asn1"
	"encoding/gob"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
)

func isError(err error) bool {
	if err != nil {
		fmt.Println(err.Error())
	}

	return (err != nil)
}

// genereate keys
func generateKeys(n int) {

	for i := 0; i < n; i++ {
		dirPath := "../keys/peer" + strconv.Itoa(i)
		if err := os.Mkdir(dirPath, 0755); err != nil && !os.IsExist(err) {
			log.Fatal(err)
		}

		// generate private and public key
		// source: https://www.socketloop.com/tutorials/golang-generate-dsa-private-public-key-and-pem-files-example
		params := new(dsa.Parameters)

		if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		privatekey := new(dsa.PrivateKey)
		privatekey.PublicKey.Parameters = *params
		dsa.GenerateKey(privatekey, rand.Reader) // this generates a public & private key pair

		var pubkey dsa.PublicKey
		pubkey = privatekey.PublicKey

		// private key file created
		privatekeyfilename := dirPath + "/private.key"
		privatekeyfile, err := os.OpenFile(privatekeyfilename, os.O_RDWR|os.O_CREATE, 0644)
		if isError(err) {
			return
		}
		privatekeyencoder := gob.NewEncoder(privatekeyfile)
		privatekeyencoder.Encode(privatekey)
		privatekeyfile.Close()

		// pub key file created
		pubkeyfilename := dirPath + "/public.key"
		pubkeyfile, err := os.OpenFile(pubkeyfilename, os.O_RDWR|os.O_CREATE, 0644)
		if isError(err) {
			return
		}

		publickeyencoder := gob.NewEncoder(pubkeyfile)
		publickeyencoder.Encode(pubkey)
		pubkeyfile.Close()

		// create pem file
		pemfile, err := os.OpenFile(dirPath+"/DSApublickey.pem", os.O_RDWR|os.O_CREATE, 0644)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		asn1Bytes, err := asn1.Marshal(pubkey)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		var pemkey = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: asn1Bytes}

		err = pem.Encode(pemfile, pemkey)

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		pemfile.Close()

	}
}

func main() {

	n := flag.Int("numPeers", 0, "number of peers to generate keys for")

	flag.Parse()
	generateKeys(*n)
}
