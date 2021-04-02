package main

import (
	"crypto/dsa"
	"crypto/md5"
	cr "crypto/rand"
	"encoding/gob"
	"flag"
	"fmt"
	"hash"
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

type Peer struct {
	listener        net.Listener     // listener to listen to other peers
	quit            chan interface{} // to hold if we are ready to stop the server
	wg              sync.WaitGroup   // used to wait for all routines to finish
	v               float64          // value of peer to propose
	i               int              // peer number
	n               int              // total number of peers
	min             float64          // minimum value that the peer has received
	numValsReceived int              // total number of values currently received by the peer
}

// creates a new pair
// i: the peer number
// n: the total number of peers
func NewPeer(i int, n int) *Peer {
	val := rand.Float64() // get a random value from 0 to 1

	// create the new peer
	p := &Peer{
		quit:            make(chan interface{}),
		v:               val,
		i:               i,
		n:               n,
		numValsReceived: 1,
		min:             val,
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
	for {
		d, err := net.Dial("tcp", "localhost:"+port)
		if err == nil {
			return d
		}
		time.Sleep(1 * time.Second)
	}
}

// function to dial to other peers.
func (p *Peer) dial() {
	defer p.wg.Done()

	var dial net.Conn

	// iterate through all peers and send this peer's value to all its other peers.
	for j := 0; j < p.n; j++ {

		// don't need to send value to itself.
		if j == p.i {
			continue
		}
		dial = getConn(j) // get the connection to the other peer j.
		defer dial.Close()

		// send value as a strong to peer j
		if _, err := dial.Write([]byte(strconv.FormatFloat(p.v, 'f', 6, 64))); err != nil {
			log.Fatal(err)
		}
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

// handle the connection from the peer
func (p *Peer) handleConnection(conn net.Conn) {

	defer conn.Close()
	buf := make([]byte, 2048)
	for {
		netData, err := conn.Read(buf) // receive data from peer

		// check for errors
		if err != nil && err != io.EOF {
			log.Println("read error", err)
			return
		}
		if netData == 0 {
			return
		}

		// parse netData to a float value.
		val, _ := strconv.ParseFloat(string(buf[:netData]), 64)

		// check if val received from peer is smaller than the current min value. If it is, update the value.
		if val < p.min {
			p.min = val
		}
		p.numValsReceived++ // increment the number of values received

		// if the number of values received is equal to n, then we can call the server to stop listening as we have
		// received all the values from the all peers in the protocol
		if p.numValsReceived == p.n {
			p.Stop()
		}
	}
}

// Usage:
//   go run peer.go <i> <n>
func main() {

	rand.Seed(time.Now().UTC().UnixNano())

	i := flag.Int("i", -1, "index number of peer")
	n := flag.Int("n", -1, "total number of peers")

	flag.Parse()
	fmt.Printf("i: %d\n", i)
	fmt.Printf("n: %d\n", n)

	// testing getting the public key
	pubKeyFile, err := os.Open("keys/peer" + strconv.Itoa(*i) + "/public.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decoder := gob.NewDecoder(pubKeyFile)

	var publickey dsa.PublicKey
	err = decoder.Decode(&publickey)

	pubKeyFile.Close()
	fmt.Printf("Public key parameter P: %v\n", publickey.Parameters.P)
	fmt.Printf("Public key parameter Q: %v\n", publickey.Parameters.Q)
	fmt.Printf("Public key parameter G: %v\n", publickey.Parameters.G)
	fmt.Printf("Public key Y: %v\n", publickey.Y)

	// testing getting the private key
	privKeyFile, err := os.Open("keys/peer" + strconv.Itoa(*i) + "/private.key")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decoderP := gob.NewDecoder(privKeyFile)

	var privatekey dsa.PrivateKey
	err = decoderP.Decode(&privatekey)

	privKeyFile.Close()
	fmt.Printf("private key parameter P: %v\n", privatekey.Parameters.P)
	fmt.Printf("private key parameter Q: %v\n", privatekey.Parameters.Q)
	fmt.Printf("private key parameter G: %v\n", privatekey.Parameters.G)
	fmt.Printf("private key X: %v\n", privatekey.X)

	var h hash.Hash
	h = md5.New()
	r := big.NewInt(0)
	s := big.NewInt(0)

	io.WriteString(h, "This is the message to be signed and verified!")
	signhash := h.Sum(nil)

	r, s, err = dsa.Sign(cr.Reader, &privatekey, signhash)
	if err != nil {
		fmt.Println(err)
	}

	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)

	fmt.Printf("Signature : %x\n", signature)

	// Verify
	verifystatus := dsa.Verify(&publickey, signhash, r, s)
	fmt.Println(verifystatus) // should be true

	// we add additional data to change the signhash
	io.WriteString(h, "This message is NOT to be signed and verified!")
	signhash = h.Sum(nil)

	verifystatus = dsa.Verify(&publickey, signhash, r, s)
	fmt.Println(verifystatus) // should be false

	p := NewPeer(*i, *n)
	fmt.Printf("Consensus Minimum Value: %f\n", p.min)
}
