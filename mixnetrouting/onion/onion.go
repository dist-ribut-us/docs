package onion

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/dist-ribut-us/crypto"
)

const (
	// IDLen in bytes  just for demo
	IDLen = 10
	// BoxIDLen is the byte length of the secret box containing the next ID
	BoxIDLen = crypto.Overhead + IDLen + 1
	// RemoveEncryption indicates that during routing a layer of encryption shoud
	// be removed
	RemoveEncryption byte = 0
	// AddEncryption indicates that during routing a layer of encryption shoud be
	// added
	AddEncryption byte = 1
)

var encode = base64.URLEncoding.EncodeToString

// PrivNode is not shared
type PrivNode struct {
	ID    []byte
	Key   *crypto.XchgPair
	Cache map[string]KeySet
	Count map[crypto.Nonce]byte
}

var zeroID = encode(make([]byte, IDLen))

// ShouldContinue returns false if the next address is Zero or in the cache
func (n *PrivNode) ShouldContinue(next []byte) bool {
	s := encode(next)
	if s == zeroID {
		return false
	}
	if n.Cache == nil {
		return true
	}
	_, inCache := n.Cache[s]
	return !inCache
}

// Open a route package. Uses the KeySet if there is one in the cache, otherwise
// uses the nodes exchange key.
func (n *PrivNode) Open(routePackage *RoutePackage) ([]byte, error) {
	if n.Cache != nil {
		ks, ok := n.Cache[encode(routePackage.Next)]
		if ok {
			return ks.Open(routePackage.Data)
		}
	}
	return n.Key.AnonOpen(routePackage.Data)
}

// NewPrivNode creates a PrivateNode with the ID set to the head of the digest
// of the public exchange key.
func NewPrivNode() *PrivNode {
	id := make([]byte, IDLen)
	key := crypto.GenerateXchgPair()
	dig := crypto.DigestFromSlice(key.Pub().Slice())
	copy(id, dig.Slice())
	return &PrivNode{
		ID:    id,
		Key:   key,
		Count: make(map[crypto.Nonce]byte),
	}
}

// String is used to generate map keys
func (n *PrivNode) String() string {
	return encode(n.ID)
}

// Pub returns the PubNode of a Private node
func (n *PrivNode) Pub() *PubNode {
	return &PubNode{
		ID:  n.ID,
		Key: n.Key.Pub(),
	}
}

// PubNode represents the data that a Private node would publish to the network
type PubNode struct {
	ID  []byte
	Key *crypto.XchgPub
}

// String is used to generate map keys
func (n *PubNode) String() string {
	return encode(n.ID)
}

// KN is used to store key/nonce pairs
type KN struct {
	Key   *crypto.Symmetric
	Nonce *crypto.Nonce
}

// KeySet is used to store receiving route keys
type KeySet struct {
	KNs     []KN
	BaseKey *crypto.XchgPriv
}

// Open removes onion layers from the receive route and applies the base key.
func (ks KeySet) Open(cipher []byte) ([]byte, error) {
	for _, kn := range ks.KNs {
		cipher = kn.Key.UnmacdOpen(cipher, kn.Nonce)
	}
	return ks.BaseKey.AnonOpen(cipher)
}

// RouteBuilder is used when constructing a route
type RouteBuilder struct {
	Next     []byte
	Data     []byte
	KNs      []KN
	ID       string
	SendMode bool
	BaseKey  *crypto.XchgPub
}

// NewSendRoute creates a RouteBuilder for direct sending
func NewSendRoute() *RouteBuilder {
	return &RouteBuilder{
		Data:     make([]byte, BoxIDLen),
		Next:     make([]byte, IDLen),
		SendMode: true,
	}
}

// NewReceiveRoute creates a RouteBuilder for creating a receive route
func (n *PrivNode) NewReceiveRoute() *RouteBuilder {
	id := make([]byte, IDLen)
	rand.Read(id)
	rb := &RouteBuilder{
		Data:     make([]byte, BoxIDLen),
		ID:       encode(id),
		SendMode: false,
		Next:     id,
	}
	rb.Push(n.Pub())
	return rb
}

// Send finishes the route building process and uses the route to construct a
// RoutePackage
func (rb *RouteBuilder) Send(msg []byte) *RoutePackage {
	if rb.BaseKey != nil {
		msg = rb.BaseKey.AnonSeal(msg)
	}
	for _, kn := range rb.KNs {
		msg = kn.Key.UnmacdSeal(msg, kn.Nonce)
	}

	cp := make([]byte, len(rb.Data))
	copy(cp, rb.Data)

	return &RoutePackage{
		RouteMsg: &RouteMsg{
			Map:  cp,
			Data: msg,
		},
		Next: rb.Next,
	}
}

// Receive take recieve RouteBuilder and turns it into a send Route builder,
// returning the route ID and KeySet.
func (rb *RouteBuilder) Receive() (string, KeySet) {
	xchg := crypto.GenerateXchgPair()
	id, kns := rb.ID, rb.KNs
	rb.ID = ""
	rb.KNs = nil
	rb.SendMode = true
	rb.BaseKey = xchg.Pub()
	ks := KeySet{
		KNs:     kns,
		BaseKey: xchg.Priv(),
	}
	return id, ks
}

// Push a Node onto the route.
func (rb *RouteBuilder) Push(n *PubNode) {
	// EX | Nonce | Enc(ES, Next|Dir ) | EncUnMAC( R )
	// EX   : ephemeral exchange key
	// Nonce: Makes process non-deterministic. Same nonce is used for all 3
	//        cryptographic operations.
	// ES   : shared key computed from ephemeral exchange key
	// Next : the next node
	// Dir  : the encryption direction
	// R    : the rest of the route

	kp := crypto.GenerateXchgPair()
	shared := kp.Shared(n.Key)
	nonce := crypto.RandomNonce()

	// nd is next|dir
	nd := make([]byte, IDLen+1)
	if rb.SendMode {
		nd[0] = RemoveEncryption
	} else {
		nd[0] = AddEncryption
	}
	copy(nd[1:], rb.Next)

	rb.Data = shared.UnmacdSeal(rb.Data, nonce)
	rb.Data = append(shared.Seal(nd, nonce), rb.Data...)
	rb.Data = append(kp.Pub().Slice(), rb.Data...)
	rb.Next = n.ID
	rb.KNs = append(rb.KNs, KN{
		Key:   shared,
		Nonce: nonce,
	})
}

// RouteMsg is what is passed between nodes
type RouteMsg struct {
	Map  []byte
	Data []byte
}

// RoutePackage represents a message in the process of being routed.
type RoutePackage struct {
	*RouteMsg
	Next []byte
	KN   KN
}

type ErrReplay struct{}

func (ErrReplay) Error() string {
	return "Route has exhausted it's replay count"
}

// Route a package. The package will be mutated so that it contains the correct
// Next ID and the RouteMsg to be sent.
func (n *PrivNode) Route(r *RoutePackage) error {
	m := r.Map
	shared := n.Key.Shared(crypto.XchgPubFromSlice(m[:crypto.KeyLength]))

	m = m[crypto.KeyLength:]
	nonce := crypto.ExtractNonce(m)
	if nonce == nil {
		return crypto.ErrDecryptionFailed
	}

	m = m[crypto.NonceLength:]
	nd, err := shared.NonceOpen(m[:BoxIDLen], nonce)
	if err != nil || len(nd) == 0 {
		return crypto.ErrDecryptionFailed
	}
	r.Next = nd[1:]
	if nd[0] == AddEncryption {
		r.Data = shared.UnmacdSeal(r.Data, nonce)
	} else {
		if c, ok := n.Count[*nonce]; ok && c == 0 {
			return ErrReplay{}
		}
		r.Data = shared.UnmacdOpen(r.Data, nonce)
		n.Count[*nonce] = 0
	}

	m = shared.UnmacdOpen(m[BoxIDLen:], nonce)
	copy(r.Map, m)
	rand.Read(r.Map[len(m):])
	return nil
}
