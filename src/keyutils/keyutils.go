package keyutils

import (
	"crypto/dsa"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
)

func getPublicKeyFromFile(peerIndex int, publickey dsa.PublicKey) {
	pubKeyFile, err := os.Open("keys/peer" + strconv.Itoa(peerIndex) + "/public.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("got form keyutils\n")

	decoder := gob.NewDecoder(pubKeyFile)
	err = decoder.Decode(&publickey)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getPrivateKeyFromFile(peerIndex int, privatekey dsa.PrivateKey) {
	privKeyFile, err := os.Open("keys/peer" + strconv.Itoa(peerIndex) + "/private.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decoder := gob.NewDecoder(privKeyFile)
	err = decoder.Decode(&privatekey)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
