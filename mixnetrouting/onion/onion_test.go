package onion

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	mr "math/rand"
	"testing"
)

func seedRand() {
	// seed math/rand with crypto/rand - just for generating the nodes
	seed := make([]byte, 4)
	rand.Read(seed)
	mr.Seed(int64(seed[0])<<24 + int64(seed[1])<<16 + int64(seed[2])<<8 + int64(seed[3]))
}

func setupDHT(nodes int) (map[string]*PrivNode, []string) {
	seedRand()
	// Simulates a DHT
	dht := make(map[string]*PrivNode, nodes)
	ids := make([]string, nodes)
	for i := range ids {
		n := NewPrivNode()
		s := n.String()
		dht[s] = n
		ids[i] = s
	}
	return dht, ids
}

func TestSend(t *testing.T) {
	totalNodes := 50
	hops := 3
	msgLen := 30

	dht, ids := setupDHT(totalNodes)

	rb := NewSendRoute()
	// Track the IDs just for testing
	hopIDs := make([]string, hops)
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		hopIDs[i] = hopID
		rb.Push(dht[hopID].Pub())
	}
	// Random message
	msg := make([]byte, msgLen)
	rand.Read(msg)
	rp := rb.Send(msg)

	for i := 0; true; i++ {
		nnID := encode(rp.Next)
		nn, ok := dht[nnID]
		if !ok {
			break
		}
		if !assert.Equal(t, hopIDs[hops-1-i], nnID) {
			return
		}
		if !assert.NoError(t, nn.Route(rp)) {
			return
		}
	}

	assert.Equal(t, msg, rp.Data)
}

func TestReceive(t *testing.T) {
	totalNodes := 50
	sendHops := 3
	receiveHops := 3
	msgLen := 30

	totalHops := sendHops + receiveHops + 1
	dht, ids := setupDHT(totalNodes)

	receiver := dht[ids[mr.Intn(totalNodes)]]
	rb := receiver.NewReceiveRoute()
	hopIDs := make([]string, totalHops) // Track the IDs just for testing
	hopIDs[0] = receiver.String()
	for i := 0; i < receiveHops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		hopIDs[i+1] = hopID
		rb.Push(dht[hopID].Pub())
	}

	routeID, ks := rb.Receive()

	for i := 0; i < sendHops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		hopIDs[i+receiveHops+1] = hopID
		rb.Push(dht[hopID].Pub())
	}
	// Random message
	msg := make([]byte, msgLen)
	rand.Read(msg)
	rp := rb.Send(msg)

	for i := 0; true; i++ {
		nnID := encode(rp.Next)
		nn, ok := dht[nnID]
		if !ok {
			break
		}
		if !assert.Equal(t, hopIDs[totalHops-1-i], nnID) {
			return
		}
		if !assert.NoError(t, nn.Route(rp)) {
			return
		}
	}

	assert.Equal(t, routeID, encode(rp.Next))
	out, err := ks.Open(rp.Data)
	assert.NoError(t, err)

	assert.Equal(t, msg, out)
}

func TestAliceToBob(t *testing.T) {
	totalNodes := 50
	bobsHops := 3
	alicesHops := 3

	dht, ids := setupDHT(totalNodes)
	bob := ids[mr.Intn(totalNodes)]

	bobsRoute := setupBobsRoute(bob, dht, ids, bobsHops)

	// At this point, Alice knows the route leads to Bob, but she can't read the
	// data in the route. Alice adds her own nodes to the route to protect her
	// anonymity
	alicesRoute := setupAlicesRoute(bobsRoute, dht, ids, alicesHops)

	msg := []byte("Hi Bob, how was your vacation?")
	rp := alicesRoute.Send(msg)

	// Simulate routing
	var curNode *PrivNode
	for curNode == nil || curNode.ShouldContinue(rp.Next) {
		curNode = dht[encode(rp.Next)]
		rp = &RoutePackage{
			RouteMsg: rp.RouteMsg,
		}
		assert.NoError(t, curNode.Route(rp))
	}

	assert.Equal(t, bob, curNode.String())
	out, err := curNode.Open(rp)
	assert.NoError(t, err)
	assert.Equal(t, msg, out)

}

func setupBobsRoute(bob string, dht map[string]*PrivNode, ids []string, hops int) *RouteBuilder {
	totalNodes := len(ids)
	bobNode := dht[bob]
	rb := bobNode.NewReceiveRoute()
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		rb.Push(dht[hopID].Pub())
	}
	id, keyset := rb.Receive()
	bobNode.Cache = make(map[string]KeySet)
	bobNode.Cache[id] = keyset
	return rb
}

func setupAlicesRoute(rb *RouteBuilder, dht map[string]*PrivNode, ids []string, hops int) *RouteBuilder {
	totalNodes := len(ids)
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		rb.Push(dht[hopID].Pub())
	}
	return rb
}

func TestReplay(t *testing.T) {
	totalNodes := 50
	hops := 3
	msgLen := 30

	dht, ids := setupDHT(totalNodes)

	rb := NewSendRoute()
	// Track the IDs just for testing
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		rb.Push(dht[hopID].Pub())
	}

	// Random message
	msg := make([]byte, msgLen)
	rand.Read(msg)
	rp := rb.Send(msg)
	for {
		nnID := encode(rp.Next)
		nn, ok := dht[nnID]
		if !ok {
			break
		}
		if !assert.NoError(t, nn.Route(rp)) {
			return
		}
	}

	assert.Equal(t, msg, rp.Data)

	rand.Read(msg)
	rp = rb.Send(msg)
	nnID := encode(rp.Next)
	nn, ok := dht[nnID]
	if !ok {
		t.Error("Did not find node")
		return
	}
	err := nn.Route(rp)
	assert.Error(t, err)
	if _, ok := err.(ErrReplay); !ok {
		t.Error("Should be ErrReplay: ", err.Error())
	}
}
