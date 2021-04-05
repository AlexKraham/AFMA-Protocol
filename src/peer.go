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

var publicKeys []dsa.PublicKey

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
	PrivateKey      dsa.PrivateKey   // private key of the peer itself
	peersReceived   []bool           // an array holding all the peers its received for this round
	roundNum        int              // current round number
	timeRun         int              // current time in seconds
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
	privateKey := getPrivateKeyFromFile(i)

	// hash value that the peer is trying to send
	signhash := getSignHash(val)
	// get signature
	signature := signMessage(i, privateKey, signhash)

	// Verify
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

	// create bool array to determine which peers we have received from so far
	peersReceived := make([]bool, n)
	peersReceived[i] = true

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
		PrivateKey:      privateKey,
		roundNum:        1,
		peersReceived:   peersReceived,
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

	// iterate through each round by dialing and sending until there are no messages to relay.
	for len(p.Relay.Messages) != 0 {
		fmt.Println("Starting round: ", p.roundNum)
		// save messages to relay and send that to dial to others
		msgsToRelay := p.Relay

		// update the relay to be empty messages, as we serve the peer, it may get populated with more messages to relay.
		var emptyMessages []MessageWithAuth
		p.Relay = Messages{
			Messages: emptyMessages,
		}
		// routine to dial to other peers and to serve(receive/listen) to peers dialing in.
		go p.dial(msgsToRelay) // send to peers
		go p.serve()           // receive from peers

		p.wg.Wait() // wait until dial and serve are finished.

		// update round number
		p.roundNum++
	}

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
		if currTime == 10 {
			// connection failed time out
			return nil
		}
	}
}

// function to dial to other peers.
func (p *Peer) dial(msgsToRelay Messages) {
	defer p.wg.Done()

	var dial net.Conn

	// iterate through all peers and send this peer's value to all its other peers.
	for j := 0; j < p.n; j++ {
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

		encoder := gob.NewEncoder(dial)
		encoder.Encode(msgsToRelay)
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

	p.wg.Add(1)
	go func() {
		p.startRoundTime()
		p.wg.Done()
	}()

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
				// start timer such that
				p.wg.Done()
			}()

		}
	}
}

func (p *Peer) resetPeersReceived() {
	for i := 0; i < len(p.peersReceived); i++ {
		if i != p.i {
			p.peersReceived[i] = false
		}
	}
}

func (p *Peer) hasReceivedFromAllPeers() bool {
	numReceived := 0
	for i := 0; i < p.n; i++ {
		if p.peersReceived[i] == true {
			numReceived++
		}
	}
	if numReceived == p.n {
		return true
	}
	return false
}

// starts the round timer, if we reach the end of the time, we should go to next round because we are timed out
// at this point
func (p *Peer) startRoundTime() {
	for i := 0; i < 5; i++ {
		time.Sleep(1 * time.Second)
		if p.hasReceivedFromAllPeers() {
			p.Stop()
			return
		}
	}

	p.Stop()
	return
}

func (p *Peer) isValidMessage(message MessageWithAuth) bool {
	if len(message.Signatures) != p.roundNum {
		return false
	}

	// store # of distinct messages
	var distinctSignatures []int

	for i := 0; i < len(message.Signatures); i++ {
		// Verify
		publicKey := publicKeys[message.Signatures[i].PeerNum]
		signhash := getSignHash(message.V)
		// get signature
		signature := message.Signatures[i]
		verifystatus := dsa.Verify(&publicKey, signhash, signature.R, signature.S)

		// add to distinct Signatures
		foundSig := false
		for j := 0; j < len(distinctSignatures); j++ {
			if message.Signatures[i].PeerNum == distinctSignatures[j] {
				foundSig = true
			}
		}
		// if we don't find the signature, its a unique signature so we should add it to the distint sigs array
		if !foundSig {
			distinctSignatures = append(distinctSignatures, message.Signatures[i].PeerNum)
		}

		// if there is any false signatures, the msg isn't valid.
		if verifystatus == false {
			return false
		}
	}

	if len(distinctSignatures) == p.roundNum {
		return true
	}
	return false
}

// check if the message value is already in the extracted array of the peer.
func (p *Peer) isMessageInExtracted(message MessageWithAuth) bool {
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

	conn.Close()

	// new messages to relay
	var newRelayMessages []MessageWithAuth

	// for all relayed messages, check
	for i := 0; i < len(messages.Messages); i++ {
		// check if message is valid
		if p.isValidMessage(messages.Messages[i]) {
			// check is message is isn't in extracted
			if !p.isMessageInExtracted(messages.Messages[i]) {
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
				newRelayMessages = append(newRelayMessages, msgWithAppendedSig)

			}

			// update min value
			if messages.Messages[i].V < p.min {
				p.min = messages.Messages[i].V
			}

			// update peer received
			p.peersReceived[messages.Messages[i].Signatures[0].PeerNum] = true
		}
	}

	// add to relay messages for next round
	p.Relay.Messages = append(p.Relay.Messages, newRelayMessages...)
}

// Usage:
//   go run peer.go <i> <n>
func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	i := flag.Int("i", -1, "index number of peer")
	n := flag.Int("n", -1, "total number of peers")
	flag.Parse()

	// create a global public section for peers to refer to
	for j := 0; j < *n; j++ {
		publicKeys = append(publicKeys, getPublicKeyFromFile(j))
	}

	p := NewPeer(*i, *n)
	fmt.Printf("Consensus Minimum Value: %f\n", p.min)
}
