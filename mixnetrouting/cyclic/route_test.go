package cyclic

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

func TestRouteEndToEnd(t *testing.T) {
	// Set the total number of nodes in the table and the number of hops to take
	totalNodes := 50
	hops := 10
	msgLen := 30000

	dht, ids := setupDHT(totalNodes)

	// Setup the route
	rb := NewRouteBuilder()
	hopIDs := make([]string, hops) // Track the IDs just for testing
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		hopIDs[i] = hopID
		rb.Push(dht[hopID].Pub())
	}
	// Random message
	msg := make([]byte, msgLen)
	rand.Read(msg)
	rt, err := rb.GetRoute(msg)
	assert.NoError(t, err)

	l0 := len(rt.Map)
	for i := 0; len(rt.Next) > 0; i++ {
		nnID := encode(rt.Next)
		nn := dht[nnID]

		rt = &RoutePackage{ // simulate sending by copying just the RouteMsg
			RouteMsg: rt.RouteMsg,
		}
		// The length of the map should stay the same
		assert.Len(t, rt.Map, l0)
		// check that we're traversing in the correct order
		assert.Equal(t, hopIDs[hops-1-i], nnID)
		// Do the actual routing
		assert.NoError(t, nn.Route(rt))
	}

	// Extract the message and check that it is correct
	out, err := rt.Final()
	assert.NoError(t, err)
	assert.Equal(t, msg, out[:msgLen])
}

func TestAliceToBob(t *testing.T) {
	totalNodes := 50
	bobsHops := 3
	alicesHops := 3

	dht, ids := setupDHT(totalNodes)
	bob := ids[mr.Intn(totalNodes)]

	bobsRoute := setupBobsRoute(bob, dht, ids, bobsHops)
	// Because Bob called SumKeys, there should only be one "key"
	assert.Len(t, bobsRoute.Keys, 1)

	// At this point, Alice knows the route leads to Bob, but she can't read the
	// data in the route. Alice adds her own nodes to the route to protect her
	// anonymity
	alicesRoute := setupAlicesRoute(bobsRoute, dht, ids, alicesHops)

	msg := []byte("Hi Bob, how was your vacation?")
	msgLen := len(msg) // assume some sort of message encoding
	rt, err := alicesRoute.GetRoute(msg)
	assert.NoError(t, err)

	// Simulate routing
	var curNode *PrivNode
	for i := 0; len(rt.Next) > 0; i++ {
		curNode = dht[encode(rt.Next)]
		rt = &RoutePackage{
			RouteMsg: rt.RouteMsg,
		}
		assert.NoError(t, curNode.Route(rt))
	}

	assert.Equal(t, bob, curNode.String())
	out, err := rt.Final()
	assert.NoError(t, err)
	assert.Equal(t, msg, out[:msgLen])

}

func setupBobsRoute(bob string, dht map[string]*PrivNode, ids []string, hops int) *RouteBuilder {
	totalNodes := len(ids)
	rb := NewRouteBuilder()
	rb.Push(dht[bob].Pub())
	for i := 0; i < hops; i++ {
		hopID := ids[mr.Intn(totalNodes)]
		rb.Push(dht[hopID].Pub())
	}
	rb.SumKeys()
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
