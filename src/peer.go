package main

import (
	"bytes"
	"crypto/dsa"
	cr "crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"reflect"
	"sort"
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

func check(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

/* ============= HASH AND SIGNATURE RELATED METHODS ============= */

func getBlockHashValue(block Block) []byte {
	blockBytes := []byte(fmt.Sprintf("%v", block))
	h := sha1.New()
	h.Write(blockBytes)
	return h.Sum(nil)
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
	ExtractedBlocks Blocks           // list of extracted blocks
	RelayBlocks     Blocks           // list of blocks to relay to other peers
	i               int              // peer number
	n               int              // total number of peers
	numValsReceived int              // total number of values currently received by the peer
	PrivateKey      dsa.PrivateKey   // private key of the peer itself
	peersReceived   []bool           // an array holding all the peers its received for this round
	roundNum        int              // current round number
	timeRun         int              // current time in seconds
	consensusBlock  Block            // store consensus block after AFMA protocol
}

type Block struct {
	Height     int64  // block height
	ParentHash []byte // parent hash
	RootHash   []byte // root hash
	Data       []byte // data
}

type Blocks struct {
	Blocks []BlockWithAuth
}

type BlockWithAuth struct {
	Block      Block
	Signatures []Signature
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

	// create data
	sha_512 := sha512.New()
	sha_512.Write([]byte(strconv.Itoa(i)))

	// create first block 0
	block0 := &Block{
		Height:     0,
		ParentHash: nil,
		RootHash:   sha_512.Sum(nil),
		Data:       []byte(strconv.Itoa(i)),
	}

	// get public and private key for this peer
	privateKey := getPrivateKeyFromFile(i)

	// create initial signed block
	blockSignHash := getBlockHashValue(*block0)
	blockSig := signMessage(i, privateKey, blockSignHash)
	var blockSigs []Signature
	blockSigs = append(blockSigs, blockSig)
	signedBlock := &BlockWithAuth{
		Block:      *block0,
		Signatures: blockSigs,
	}

	// create array of blocks with auth
	var blockArray []BlockWithAuth
	blockArray = append(blockArray, *signedBlock)

	blocks := Blocks{
		Blocks: blockArray,
	}

	// create bool array to determine which peers we have received from so far
	peersReceived := make([]bool, n)
	peersReceived[i] = true

	// create the new peer
	p := &Peer{
		quit:            make(chan interface{}),
		ExtractedBlocks: blocks,
		RelayBlocks:     blocks,
		i:               i,
		n:               n,
		numValsReceived: 1,
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

	for len(p.RelayBlocks.Blocks) != 0 {
		fmt.Println("Starting round #", p.roundNum, " of consensus algorithm")
		blocksToRelay := p.RelayBlocks

		var emptyBlocks []BlockWithAuth
		p.RelayBlocks = Blocks{
			Blocks: emptyBlocks,
		}

		go p.dial(blocksToRelay)
		go p.serve()

		p.wg.Wait()

		p.roundNum++
	}

	// after going through AFMA protocol, we have an extracted list of blocks, now we can create our consensus block
	p.setConsensusBlock()

	return p
}

type RootHash struct {
	B []byte
}

func (p *Peer) setConsensusBlock() {
	minRootHash := p.ExtractedBlocks.Blocks[0].Block.RootHash
	minIndex := 0

	blocks := p.ExtractedBlocks.Blocks

	var rootHashList []RootHash
	rootHashList = append(rootHashList, RootHash{B: minRootHash})

	for i := 1; i < len(blocks); i++ {
		// if current parent hash is less than current min, update the min values.
		if bytes.Compare(blocks[i].Block.RootHash, minRootHash) == -1 {
			minRootHash = blocks[i].Block.RootHash
			minIndex = i
		}

		rootHashList = append(rootHashList, RootHash{B: blocks[i].Block.RootHash})
	}

	// order the list
	sort.Slice(rootHashList, func(i, j int) bool {
		if bytes.Compare(rootHashList[i].B, rootHashList[j].B) == -1 {
			return true
		}
		return false
	})

	// concatenate all bytes together
	var newData []byte
	for i := 0; i < len(rootHashList); i++ {
		newData = append(newData, rootHashList[i].B...)
	}

	sha_512 := sha512.New()
	sha_512.Write(newData)
	newRootHash := sha_512.Sum(nil)

	newBlock := Block{
		Height:     blocks[minIndex].Block.Height + 1,
		ParentHash: blocks[minIndex].Block.RootHash,
		RootHash:   newRootHash,
		Data:       newData,
	}

	p.consensusBlock = newBlock
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
func (p *Peer) dial(blocksToRelay Blocks) {
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
		encoder.Encode(blocksToRelay)
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

// make sure auth has correct # of signatures
func (p *Peer) isValidBlock(block BlockWithAuth) bool {
	if len(block.Signatures) != p.roundNum {
		return false
	}
	var distinctSignatures []int

	for i := 0; i < len(block.Signatures); i++ {
		// Verify
		publicKey := publicKeys[block.Signatures[i].PeerNum]
		signhash := getBlockHashValue(block.Block)
		// get signature
		signature := block.Signatures[i]
		verifystatus := dsa.Verify(&publicKey, signhash, signature.R, signature.S)

		// add to distinct Signatures
		foundSig := false
		for j := 0; j < len(distinctSignatures); j++ {
			if block.Signatures[i].PeerNum == distinctSignatures[j] {
				foundSig = true
			}
		}
		// if we don't find the signature, its a unique signature so we should add it to the distint sigs array
		if !foundSig {
			distinctSignatures = append(distinctSignatures, block.Signatures[i].PeerNum)
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

// check if the block is already in the extracted array of the peer.
func (p *Peer) isBlockInExtracted(block BlockWithAuth) bool {
	for i := 0; i < len(p.ExtractedBlocks.Blocks); i++ {
		if reflect.DeepEqual(block, p.ExtractedBlocks.Blocks[i]) {
			return true
		}
	}
	return false
}

// handle the connection from the peer
func (p *Peer) handleConnection(conn net.Conn) {

	// get all blocks that have been relayed by peer
	dec := gob.NewDecoder(conn)
	blocks := &Blocks{}
	dec.Decode(blocks)

	conn.Close()

	var newRelayBlocks []BlockWithAuth

	// for all relayed messages, check
	for i := 0; i < len(blocks.Blocks); i++ {
		// check if block is valid
		if p.isValidBlock(blocks.Blocks[i]) {
			// check if block s in extracted
			if !p.isBlockInExtracted(blocks.Blocks[i]) {
				// sign the message
				signature := signMessage(p.i, p.PrivateKey, getBlockHashValue(blocks.Blocks[i].Block))

				blockWithAppendedSig := BlockWithAuth{
					Block:      blocks.Blocks[i].Block,
					Signatures: append(blocks.Blocks[i].Signatures, signature),
				}

				// union extracted with the msg
				p.ExtractedBlocks = Blocks{
					Blocks: append(p.ExtractedBlocks.Blocks, blockWithAppendedSig),
				}

				// union relay with {s}
				newRelayBlocks = append(newRelayBlocks, blockWithAppendedSig)

			}

			// update peer received
			p.peersReceived[blocks.Blocks[i].Signatures[0].PeerNum] = true
		}
	}

	// add to relay messages for next round
	p.RelayBlocks.Blocks = append(p.RelayBlocks.Blocks, newRelayBlocks...)
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

	fmt.Println("Consensus Block: ", p.consensusBlock)
}
