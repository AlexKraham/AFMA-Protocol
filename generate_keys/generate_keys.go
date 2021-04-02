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

	// create public key file
	// fileName := "../keys/public_keys.txt"
	// publicKeyFile, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	// if isError(err) {
	// 	return
	// }

	// create private key files
	// for i := 0; i < n; i++ {

	// 	// generate private and public key
	// 	// source: https://www.socketloop.com/tutorials/golang-generate-dsa-private-public-key-and-pem-files-example
	// 	params := new(dsa.Parameters)

	// 	if err := dsa.GenerateParameters(params, rand.Reader, dsa.L1024N160); err != nil {
	// 		fmt.Println(err)
	// 		os.Exit(1)
	// 	}

	// 	privatekey := new(dsa.PrivateKey)
	// 	privatekey.PublicKey.Parameters = *params
	// 	dsa.GenerateKey(privatekey, rand.Reader) // this generates a public & private key pair

	// 	var pubkey dsa.PublicKey
	// 	pubkey = privatekey.PublicKey
	// 	// fmt.Printf("pubkey: %s\n", pubkey.Y.String())
	// 	fmt.Printf("pubkey: %x\n", pubkey)

	// 	// wrinte to public key file
	// 	// _, err = publicKeyFile.WriteString(pubkey.Y.String())
	// 	// if isError(err) {
	// 	// 	return
	// 	// }

	// 	// pub key file created
	// 	fileName := "../keys/peer" + strconv.Itoa(i) + "/pubkey.txt"
	// 	file, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE, 0644)
	// 	if isError(err) {
	// 		return
	// 	}

	// 	_, err = file.WriteString("HELLO \n")
	// 	if isError(err) {
	// 		return
	// 	}

	// 	// Save file changes.
	// 	err = file.Sync()
	// 	if isError(err) {
	// 		return
	// 	}
	// }

}

func main() {

	n := flag.Int("numPeers", 0, "number of peers to generate keys for")

	flag.Parse()
	fmt.Printf("helo\n")

	generateKeys(*n)
}
