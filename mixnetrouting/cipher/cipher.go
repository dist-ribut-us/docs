package cipher

import (
	"crypto/rand"
	"github.com/dist-ribut-us/errors"
	"math/big"
)

// 70035030982873223990326147545273826083163227324677473758120515445066011271064596346550284227444737
// (2*571)^32 + 1
// A larger prime may be needed
var (
	p = new(big.Int).SetBytes([]byte{
		32, 201, 195, 52, 180, 51, 194, 228, 73, 211, 71, 87, 253,
		82, 32, 232, 27, 223, 96, 40, 188, 105, 158, 196, 189, 36,
		148, 33, 216, 20, 50, 221, 59, 70, 142, 71, 129, 0, 0, 0, 1,
	})
	bigZero      = big.NewInt(0)
	bigOne       = big.NewInt(1)
	bigTwo       = big.NewInt(2)
	phi          = new(big.Int).Sub(p, bigOne)
	pLen         = len(p.Bytes())
	primeFactors = []*big.Int{big.NewInt(2), big.NewInt(571)}
)

const (
	// ErrWrongLength is returned when a key of incorrect length is used.
	ErrWrongLength errors.String = "Cipher must be a multiple of the prime length"
)

// PrimeLength returns the byte length of the prime
func PrimeLength() int { return pLen }

// Cipher holds the enciphered data and the cipher accumulator
type Cipher struct {
	Data []byte
	Acc  *big.Int
}

// Cycle applies a cyclic key to the cipher. It chooses a random value and adds
// that to both the key and the accumulator.
func (c *Cipher) Cycle(key []byte) error {
	if len(c.Data)%pLen != 0 {
		return ErrWrongLength
	}

	rnd := make([]byte, pLen+1)
	rand.Read(rnd)
	bigRnd := new(big.Int).SetBytes(rnd)
	bigRnd.Mod(bigRnd, phi)
	k := new(big.Int).SetBytes(key)

	k.Mod(k.Add(k, bigRnd), phi)
	c.Acc.Mod(c.Acc.Add(c.Acc, bigRnd), phi)

	c.cycle(k)
	return nil
}

// cycle is the core of the algorithm shared by both the exposed Cycle method
// the Final method. It deterministically applies a key to the cipher data.
func (c *Cipher) cycle(key *big.Int) {
	// z is declared to be reused as intermediary portion of the calculation
	// it doesn't have any special meaning
	z := new(big.Int)
	bigC := new(big.Int)
	g := newGenerator()
	out := make([]byte, len(c.Data))
	for i := 0; i*pLen < len(c.Data); i++ {
		bigC.SetBytes(c.Data[i*pLen : (i+1)*pLen])
		// c = (c * r^k) % p
		z.Exp(g.next(), key, p)
		bigC.Mul(bigC, z)
		bigC.Mod(bigC, p)
		bs := bigC.Bytes()
		copy(out[(i*pLen)+(pLen-len(bs)):], bs)
	}
	c.Data = out
}

// Start the cyclic cipher
func Start(keys [][]byte, msg []byte) (*Cipher, error) {
	sum := sumKeys(keys)
	c := &Cipher{
		Data: prepMsg(msg),
		Acc:  new(big.Int),
	}
	return c, c.Cycle(sum.Sub(phi, sum).Bytes())
}

// Final is called to finish the cipher, it compensates for the accumulator and
// removes the leading zero from each segment. It does not remove trailing
// zeros.
func (c *Cipher) Final() ([]byte, error) {
	if len(c.Data)%pLen != 0 {
		return nil, ErrWrongLength
	}
	c.Acc.Sub(c.Acc.Neg(c.Acc), phi)
	c.Acc.Mod(c.Acc, phi)
	c.cycle(c.Acc)
	return finishMsg(c.Data), nil
}

// generator for primitive roots
type generator struct {
	r *big.Int
	i int
}

func newGenerator() *generator {
	return &generator{
		r: new(big.Int).Set(bigOne),
	}
}

// The first time a generator is used it populates this table, on all subsequent
// runs, it just does a look up.
var rootTbl []*big.Int

func (g *generator) next() *big.Int {
	// first check the root table
	if g.i < len(rootTbl) {
		g.r.Set(rootTbl[g.i])
		g.i++
		return g.r
	}

	// z is used for intermediate calculations
	z := new(big.Int)
	for {
		g.r.Add(g.r, bigOne)
		isR := true

		for _, pf := range primeFactors {
			// r is a primitive root if for every prime factor
			// r^(phi/pf) % p != 1
			z.Div(phi, pf)
			z.Exp(g.r, z, p)
			if z.Cmp(bigOne) == 0 {
				isR = false
				break
			}
		}

		if isR {
			rootTbl = append(rootTbl, new(big.Int).Set(g.r))
			g.i++
			return g.r
		}
	}
}

// prepMsg breaks the message into chunks that are guaranteed to be less than
// p by taking sections one byte shorter than p and padding them with a leading
// zero. It also pad the tail with enough zeros to round out the length.
func prepMsg(m []byte) []byte {
	l := len(m) % (pLen - 1)
	if l != 0 {
		b := make([]byte, pLen-1-l)
		m = append(m, b...)
	}
	out := make([]byte, (len(m)/(pLen-1))*pLen)

	for i := 0; i*(pLen-1) < len(m); i++ {
		copy(out[i*pLen+1:], m[i*(pLen-1):(i+1)*(pLen-1)])
	}
	return out
}

// finishMsg removes the zeros added to each segment by prepMsg, but it does not
// remove the trailing zeros.
func finishMsg(c []byte) []byte {
	if len(c)%pLen != 0 {
		return nil
	}

	out := make([]byte, (len(c)/pLen)*(pLen-1))
	for i := 0; i*pLen < len(c); i++ {
		copy(out[i*(pLen-1):], c[i*pLen+1:(i+1)*pLen])
	}
	return out
}

func sumKeys(keys [][]byte) *big.Int {
	sum := big.NewInt(0)
	for _, k := range keys {
		sum.Add(sum, new(big.Int).SetBytes(k))
	}
	return sum.Mod(sum, phi)
}

// SumKeys returns the sum of the keys as a byte slice. This avoids directly
// dealing with big.Int outside of this package.
func SumKeys(keys [][]byte) []byte {
	return sumKeys(keys).Bytes()
}
