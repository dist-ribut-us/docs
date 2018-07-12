package cyclic

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/dist-ribut-us/crypto"
	"github.com/dist-ribut-us/docs/mixnetrouting/cyclic/cipher"
)

const (
	// IDLen in bytes  just for demo
	IDLen = 10
	// BoxIDLen is the byte length of the secret box containing the next ID
	BoxIDLen = crypto.Overhead + IDLen
)

var encode = base64.URLEncoding.EncodeToString

// PrivNode is not shared
type PrivNode struct {
	ID  []byte
	Key *crypto.XchgPair
}

// NewPrivNode creates a PrivateNode with the ID set to the head of the digest
// of the public exchange key.
func NewPrivNode() *PrivNode {
	id := make([]byte, IDLen)
	key := crypto.GenerateXchgPair()
	dig := crypto.DigestFromSlice(key.Pub().Slice())
	copy(id, dig.Slice())
	return &PrivNode{
		ID:  id,
		Key: key,
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

// RouteBuilder is used when constructing a route
type RouteBuilder struct {
	Next []byte
	Data []byte
	Keys [][]byte
}

// NewRouteBuilder creates an empty route
func NewRouteBuilder() *RouteBuilder {
	return &RouteBuilder{}
}

// GetRoute finishes the route building process.
func (rb *RouteBuilder) GetRoute(msg []byte) (*RoutePackage, error) {
	c, err := cipher.Start(rb.Keys, msg)
	if err != nil {
		return nil, err
	}

	return &RoutePackage{
		RouteMsg: &RouteMsg{
			Map:    rb.Data,
			Cipher: c,
		},
		Next: rb.Next,
	}, nil
}

// SumKeys replaces the keys in the Route Builder with their sum allowing the
// RouteBuilder to be shared without revealing the keys.
func (rb *RouteBuilder) SumKeys() {
	rb.Keys = [][]byte{cipher.SumKeys(rb.Keys)}
}

// Push a Node onto the route.
func (rb *RouteBuilder) Push(n *PubNode) {
	// C_x | Nonce | E(C_s, N_l) | E_umac(C_s, r)
	// N_l : id of the next node
	// C_x : exchange key for c
	// C_s : symmetric key with c
	//   r : the remainder of the route
	kp := crypto.GenerateXchgPair()
	shared := kp.Shared(n.Key)

	nonce := crypto.RandomNonce()
	rb.Data = shared.UnmacdSeal(rb.Data, nonce)
	rb.Data = append(shared.Seal(rb.Next, nonce), rb.Data...)
	rb.Data = append(kp.Pub().Slice(), rb.Data...)
	rb.Next = n.ID

	ck := cipherKey(shared, nonce)
	rb.Keys = append(rb.Keys, ck)
}

func cipherKey(shared *crypto.Symmetric, nonce *crypto.Nonce) []byte {
	// Including the nonce behaves as a salt
	return append(shared.Slice(), nonce.Slice()...)
}

// RouteMsg is what is passed between nodes
type RouteMsg struct {
	Map []byte
	*cipher.Cipher
}

// RoutePackage represents a message in the process of being routed.
type RoutePackage struct {
	*RouteMsg
	Next []byte
	CK   []byte // cipher key
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

	var err error
	if len(r.Map) > BoxIDLen {
		r.Next, err = shared.NonceOpen(m[:BoxIDLen], nonce)
		// A decryption failure may not be an actual error, it may mean that we're
		// done routing.
		if err != nil {
			r.Next = nil
			r.Map = nil
		} else {
			m = shared.UnmacdOpen(m[BoxIDLen:], nonce)
			copy(r.Map, m)
			rand.Read(r.Map[len(m):])
		}
	} else {
		r.Next = nil
		r.Map = nil
	}

	r.CK = cipherKey(shared, nonce)
	return r.Cycle(r.CK)
}
