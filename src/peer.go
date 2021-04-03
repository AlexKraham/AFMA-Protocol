package main

import (
	"crypto/dsa"
	cr "crypto/rand"
	"crypto/sha1"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func getPublicKeyFromFile(peerIndex int) dsa.PublicKey {
	var publickey dsa.PublicKey
	pubKeyFile, err := os.Open("keys/peer" + strconv.Itoa(peerIndex) + "/public.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decoder := gob.NewDecoder(pubKeyFile)
	err = decoder.Decode(&publickey)

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	pubKeyFile.Close()

	return publickey
}

func getPrivateKeyFromFile(peerIndex int) dsa.PrivateKey {
	var privatekey dsa.PrivateKey
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

	privKeyFile.Close()

	return privatekey
}

/* ============= HASH AND SIGNATURE RELATED METHODS ============= */

// get the H(m), or otherwise the hash of the message
// returns an array of bytes
func getSignHash(m float64) []byte {
	h := sha1.New()
	io.WriteString(h, fmt.Sprintf("%f", m))
	signhash := h.Sum(nil)

	return signhash
}

func signMessage(i int, privateKey dsa.PrivateKey, signhash []byte) Signature {
	r, s, err := dsa.Sign(cr.Reader, &privateKey, signhash)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("R VALUE: - ITSELF %d\n", r)

	signaturebytes := r.Bytes()
	signaturebytes = append(signaturebytes, s.Bytes()...)

	signature := &Signature{
		Signature: signaturebytes,
		R:         r,
		S:         s,
		PeerNum:   i,
	}

	return *signature
}

/* ============= PEER RELATED METHODS ============= */
type Peer struct {
	listener        net.Listener     // listener to listen to other peers
	quit            chan interface{} // to hold if we are ready to stop the server
	wg              sync.WaitGroup   // used to wait for all routines to finish
	v               float64          // value of peer to propose
	Messages        Messages         // messages with authentication
	Extracted       Messages         // messages that have been extracted
	Relay           Messages         // messages to relay
	i               int              // peer number
	n               int              // total number of peers
	min             float64          // minimum value that the peer has received
	numValsReceived int              // total number of values currently received by the peer
	PrivateKey      dsa.PrivateKey
	PublicKey       dsa.PublicKey
	roundNum        int // current round number
}

type Messages struct {
	Messages []MessageWithAuth
}

type MessageWithAuth struct {
	V          float64     // value of the peer
	Signatures []Signature // list of signatures
}

type Signature struct {
	Signature []byte
	R         *big.Int
	S         *big.Int
	PeerNum   int
}

// creates a new pair
// i: the peer number
// n: the total number of peers
func NewPeer(i int, n int) *Peer {
	val := rand.Float64() // get a random value from 0 to 1

	// get public and private key for this peer
	publicKey := getPublicKeyFromFile(i)
	privateKey := getPrivateKeyFromFile(i)

	// hash value that the peer is trying to send
	signhash := getSignHash(val)
	// get signature
	signature := signMessage(i, privateKey, signhash)

	// // Verify
	// verifystatus := dsa.Verify(&publicKey, signhash, signature.r, signature.s)
	// fmt.Printf("should be true here \n")
	// fmt.Println(verifystatus) // should be true
	var signatures []Signature
	signatures = append(signatures, signature)
	// create initial array with peer's own signed message
	signedMessage := &MessageWithAuth{
		V:          val,
		Signatures: signatures,
	}

	// create array of messages with auth
	var messageArray []MessageWithAuth
	messageArray = append(messageArray, *signedMessage)

	messages := Messages{
		Messages: messageArray,
	}

	// create the new peer
	p := &Peer{
		quit:            make(chan interface{}),
		v:               val,
		Messages:        messages,
		Extracted:       messages,
		Relay:           messages,
		i:               i,
		n:               n,
		numValsReceived: 1,
		min:             val,
		PublicKey:       publicKey,
		PrivateKey:      privateKey,
		roundNum:        1,
	}

	// get the port address based on the peer number, i.
	addr := getPort(i)

	// start listening on port address.
	l, err := net.Listen("tcp", "localhost:"+addr)
	if err != nil {
		log.Fatal(err)
	}

	p.listener = l

	p.wg.Add(2)

	// routine to dial to other peers and to serve(receive/listen) to peers dialing in.
	go p.dial()  // send to peers
	go p.serve() // receive from peers

	p.wg.Wait() // wait until dial and serve are finished.
	return p
}

// function to get the port string address based on the peer number.
// i.e. Peer #3 := 9000 + (3 * 4) = 9012.
// This means peer #3 will start listening on port 9012, so if we have another peer looking to dial to peer #3,
// they can dial to localhost:9012 and send a message to that port.
func getPort(offset int) string {
	port_num := 9000 + (offset * 4)
	return strconv.Itoa(port_num)
}

// Utilizing getPort(offset int) function above, we will dial the port for the specified peer and return the connection.
// Because some peers may start dialing before other peers severs has started, we create a for loop to attempt to connect every second
// At some point, we should timeout in the future iterations of this code.
func getConn(offset int) net.Conn {
	port := getPort(offset)
	currTime := 0
	for {
		d, err := net.Dial("tcp", "localhost:"+port)
		if err == nil {
			return d
		}
		time.Sleep(1 * time.Second)
		currTime++
		if currTime == 60 {
			// connection failed time out
			return nil
		}
	}
}

// function to dial to other peers.
func (p *Peer) dial() {
	defer p.wg.Done()

	var dial net.Conn

	// iterate through all peers and send this peer's value to all its other peers.
	for j := 0; j < p.n; j++ {
		// fmt.Println("j: ", j)

		// don't need to send value to itself.
		if j == p.i {
			continue
		}

		dial = getConn(j) // get the connection to the other peer j.
		if dial == nil {
			// connection timed out
			fmt.Println("Connection timed out, failed to dial peer #", j)
			continue
		}
		defer dial.Close()

		// msg := "-r "
		// rStr := []byte(p.messages[0].signatures[0].r.Bytes())
		// rStr := p.Messages[0].Signatures[0].R.String()
		// msg = msg + rStr

		encoder := gob.NewEncoder(dial)
		encoder.Encode(p.Relay)
		fmt.Println("messages to relay: ", p.Relay)

		// var b bytes.Buffer
		// e := gob.NewEncoder(&b)
		// if err := e.Encode(p); err != nil {
		// 	panic(err)
		// }

		// if _, err := dial.Write(b.Bytes()); err != nil {
		// 	log.Fatal(err)
		// }
		// fmt.Println("MY OWN PRIVATE KEY: ", p.PrivateKey)
		// fmt.Println("Encoded Struc?t ", b)

		// var p2 Peer
		// d := gob.NewDecoder(&b)
		// if err := d.Decode(&p2); err != nil {
		// 	panic(err)
		// }

		// fmt.Println("Decoded Struct PRIVATE:  ", p2.PrivateKey)

		// send value message
		// if _, err := dial.Write([]byte(msg)); err != nil {
		// 	log.Fatal(err)
		// }

		// // send s mssg
		// msg = "-s "
		// // rStr := []byte(p.messages[0].signatures[0].r.Bytes())
		// sStr := p.messages[0].signatures[0].s.String()
		// msg = msg + sStr

		// if _, err := dial.Write([]byte(msg)); err != nil {
		// 	log.Fatal(err)
		// }
		// // if _, err := dial.Write([]byte(strconv.FormatFloat(p.messages[0].v, 'f', 6, 64))); err != nil {
		// 	log.Fatal(err)
		// }

		// send value as a string to peer j
		// if _, err := dial.Write([]byte(strconv.FormatFloat(p.v, 'f', 6, 64))); err != nil {
		// 	log.Fatal(err)
		// }
	}
}

// function to stop the peer server from running
func (p *Peer) Stop() {
	close(p.quit)      // close the channel
	p.listener.Close() // close the listener
}

// Serve function so that peer can receive and accept connections from other peers
func (p *Peer) serve() {
	fmt.Printf("Peer %d of %d Started...\n", p.i, p.n-1)
	fmt.Printf("Value For Peer %d to Send: %f\n", p.i, p.v)
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			select {
			case <-p.quit: // in the case the channel is closed, we end the function, calling p.wg.Done() and ending server.
				return
			default:
				log.Println("accept error", err)
			}
		} else {
			p.wg.Add(1)
			go func() {
				p.handleConnection(conn) // handle the connection from a peer attempting to send a value
				p.wg.Done()
			}()
		}
	}
}

func isValidMessage(p *Peer, message MessageWithAuth) bool {
	if len(message.Signatures) != p.roundNum {
		return false
	}

	for i := 0; i < len(message.Signatures); i++ {
		// Verify
		// might need to create a variable that contains all the public keys for all the peers
		publicKey := getPublicKeyFromFile(message.Signatures[i].PeerNum)
		signhash := getSignHash(message.V)
		// get signature
		// signature := signMessage(i, privateKey, signha?sh)
		signature := message.Signatures[i]
		verifystatus := dsa.Verify(&publicKey, signhash, signature.R, signature.S)
		fmt.Printf("should be true here \n")
		fmt.Println(verifystatus) // should be true
		if verifystatus == false {
			return false
		}
	}

	return true
}

func isMessageInExtracted(p *Peer, message MessageWithAuth) bool {
	for i := 0; i < len(p.Extracted.Messages); i++ {
		if message.V == p.Extracted.Messages[i].V {
			return true
		}
	}

	return false
}

// handle the connection from the peer
func (p *Peer) handleConnection(conn net.Conn) {
	// receive round k messages from peer

	// get all messages that have been relayed by peer
	dec := gob.NewDecoder(conn)
	messages := &Messages{}
	dec.Decode(messages)
	fmt.Println("RECEIVED: ", messages)
	conn.Close()

	// var messagesToRelay []MessageWithAuth

	// new messages to relay
	var newRelayMessages []MessageWithAuth

	// for all relayed messages, check
	for i := 0; i < len(messages.Messages); i++ {
		// check if message is valid
		if isValidMessage(p, messages.Messages[i]) {
			// check is message is isn't in extracted
			if !isMessageInExtracted(p, messages.Messages[i]) {
				// var updatedExtractedMessages []MessageWithAuth
				// updatedExtractedMessages = append(p.Extracted.Messages, messages.Messages...)

				// sign the message
				signature := signMessage(p.i, p.PrivateKey, getSignHash(messages.Messages[i].V))
				msgWithAppendedSig := MessageWithAuth{
					V:          messages.Messages[i].V,
					Signatures: append(messages.Messages[i].Signatures, signature),
				}

				// union extracted with the msg
				p.Extracted = Messages{
					Messages: append(p.Extracted.Messages, msgWithAppendedSig),
				}
				// union relay with {s}
				// p.Relay = Messages{
				// 	Messages : append(p.Relay.Messages, msgWithAppendedSig),
				// }
				newRelayMessages = append(newRelayMessages, msgWithAppendedSig)
			}

			// update min value
			if messages.Messages[i].V < p.min {
				p.min = messages.Messages[i].V
			}

			p.numValsReceived++ // increment the number of values received

			// check if we are done

			if p.numValsReceived == p.n {
				p.Stop()
			}
		}
	}

	// defer conn.Close()
	// buf := make([]byte, 4096)
	// for {

	// netData, err := conn.Read(buf) // receive data from peer

	// // check for errors
	// if err != nil && err != io.EOF {
	// 	log.Println("read error", err)
	// 	return
	// }
	// if netData == 0 {
	// 	return
	// }

	// // var b bytes.Buffer

	// fmt.Printf("RECEIVED: %s\n", string(buf[:netData]))

	// words := strings.Fields(string(buf[:netData]))
	// fmt.Println(words)

	// test := new(big.Int)
	// test.SetBytes(buf[:netData])
	// x, err := fmt.Sscan(string(buf[:netData]), test)
	// if err != nil {
	// 	log.Println("error scanning value:", err)
	// } else {
	// 	fmt.Println(test)
	// }
	// fmt.Println(test)

	// // parse netData to a float value.
	// val, _ := strconv.ParseFloat(string(buf[:netData]), 64)

	// // check if val received from peer is smaller than the current min value. If it is, update the value.
	// if val < p.min {
	// 	p.min = val
	// }
	// p.numValsReceived++ // increment the number of values received

	// // if the number of values received is equal to n, then we can call the server to stop listening as we have
	// // received all the values from the all peers in the protocol
	// if p.numValsReceived == p.n {
	// 	p.Stop()
	// }
	// }
}

// Usage:
//   go run peer.go <i> <n>
func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	i := flag.Int("i", -1, "index number of peer")
	n := flag.Int("n", -1, "total number of peers")

	flag.Parse()
	// fmt.Printf("i: %d\n", i)
	// fmt.Printf("n: %d\n", n)

	// publickey := getPublicKeyFromFile(*i)
	// // keyutils.getPublicKeyFromFile(i, publickey)
	// // testing getting the public key
	// // pubKeyFile, err := os.Open("keys/peer" + strconv.Itoa(*i) + "/public.key")
	// // if err != nil {
	// // 	fmt.Println(err)
	// // 	os.Exit(1)
	// // }

	// // decoder := gob.NewDecoder(pubKeyFile)

	// // var publickey dsa.PublicKey
	// // err = decoder.Decode(&publickey)

	// // pubKeyFile.Close()
	// fmt.Printf("Public key parameter P: %v\n", publickey.Parameters.P)
	// fmt.Printf("Public key parameter Q: %v\n", publickey.Parameters.Q)
	// fmt.Printf("Public key parameter G: %v\n", publickey.Parameters.G)
	// fmt.Printf("Public key Y: %v\n", publickey.Y)

	// // testing getting the private key
	// privKeyFile, err := os.Open("keys/peer" + strconv.Itoa(*i) + "/private.key")
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// // decoderP := gob.NewDecoder(privKeyFile)

	// // var privatekey dsa.PrivateKey
	// // err = decoderP.Decode(&privatekey)
	// privatekey := getPrivateKeyFromFile(*i)

	// privKeyFile.Close()
	// fmt.Printf("private key parameter P: %v\n", privatekey.Parameters.P)
	// fmt.Printf("private key parameter Q: %v\n", privatekey.Parameters.Q)
	// fmt.Printf("private key parameter G: %v\n", privatekey.Parameters.G)
	// fmt.Printf("private key X: %v\n", privatekey.X)

	// var h hash.Hash
	// h = md5.New()
	// r := big.NewInt(0)
	// s := big.NewInt(0)

	// io.WriteString(h, "This is the message to be signed and verified!")
	// signhash := h.Sum(nil)

	// r, s, err = dsa.Sign(cr.Reader, &privatekey, signhash)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// signature := r.Bytes()
	// signature = append(signature, s.Bytes()...)

	// fmt.Printf("Signature : %x\n", signature)

	// // Verify
	// verifystatus := dsa.Verify(&publickey, signhash, r, s)
	// fmt.Println(verifystatus) // should be true

	// // we add additional data to change the signhash
	// io.WriteString(h, "This message is NOT to be signed and verified!")
	// signhash = h.Sum(nil)

	// verifystatus = dsa.Verify(&publickey, signhash, r, s)
	// fmt.Println(verifystatus) // should be false

	p := NewPeer(*i, *n)
	fmt.Printf("Consensus Minimum Value: %f\n", p.min)
}
