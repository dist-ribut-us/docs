package cipher

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func GenerateKeys(n int) [][]byte {
	keys := make([][]byte, n)
	for i := range keys {
		rnd := make([]byte, (pLen - 1))
		rand.Read(rnd)
		keys[i] = rnd
	}
	return keys
}

func TestEndToEnd(t *testing.T) {
	msgLn := 60000

	keys := GenerateKeys(10)

	msg := make([]byte, msgLn)
	rand.Read(msg)

	c, err := Start(keys, msg)
	assert.NoError(t, err)

	for _, k := range keys {
		err = c.Cycle(k)
		assert.NoError(t, err)
	}

	out, err := c.Final()
	assert.NoError(t, err)

	assert.Equal(t, msg, out[:msgLn])
}

func TestPrepAndFinishMsg(t *testing.T) {
	msgLn := 60000
	msg := make([]byte, msgLn)
	rand.Read(msg)

	assert.Equal(t, msg, finishMsg(prepMsg(msg)))
}
