/*
 * Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2018, University of California, Berkeley
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

package bls12381

import (
	"crypto/rand"
	"flag"
	"math/big"
	"os"
	"testing"

	"github.com/samkumar/embedded-pairing/lang/go/cryptutils"
)

var testStdIters = 1000
var testFewIters = 100

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		testStdIters = 30
		testFewIters = 10
	}
	os.Exit(m.Run())
}

func TestGroupOrder(t *testing.T) {
	p, _ := new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)
	if p.Cmp(GroupOrder) != 0 {
		t.Fatal("GroupOrder is incorrect")
	}
}

func TestG1Zero(t *testing.T) {
	a := new(G1Affine).Copy(G1ZeroAffine)
	b := new(G1).FromAffine(a)
	c := new(G1Affine).FromProjective(b)
	if !G1AffineEqual(a, c) {
		t.Fatal("Zero not copied/converted correctly")
	}
}

func TestG1AffineConversion(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G1).Random()
		b := new(G1Affine).FromProjective(a)
		c := new(G1).FromAffine(b)
		if !G1Equal(a, c) {
			t.Fatal("Converting to affine and back resulted in different element")
		}
	}
}

func TestG1Double(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G1).Random()
		b := new(G1).Double(a)
		c := new(G1).Copy(a)
		a.Add(a, c)
		if !G1Equal(a, b) {
			t.Fatal("Double does not match self-addition")
		}
	}
}

func TestG1AffineDouble(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G1).Random()
		b := new(G1).Double(a)
		c := new(G1Affine).FromProjective(a)
		a.AddMixed(a, c)
		if !G1Equal(a, b) {
			t.Fatal("Double does not match affine self-addition")
		}
	}
}

func TestG1Negate(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G1).Random()
		b := new(G1).Negate(a)
		a.Add(a, b)
		if !G1Equal(a, G1Zero) {
			t.Fatal("Element plus negation is not zero")
		}
	}
}

func TestG1AffineNegate(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G1).Random()
		b := new(G1Affine).FromProjective(a)
		b.Negate(b)
		a.AddMixed(a, b)
		if !G1Equal(a, G1Zero) {
			t.Fatal("Element plus negation is not zero")
		}
	}
}

func TestG1Multiply(t *testing.T) {
	for i := 0; i != 100; i++ {
		a := new(G1).Random()
		curr := new(G1).Copy(G1Zero)
		for j := 0; j != testStdIters; j++ {
			result := new(G1).Multiply(a, big.NewInt(int64(j)))
			if !G1Equal(result, curr) {
				t.Fatal("Multiplication does not match repeated addition")
			}
			curr.Add(curr, a)
		}
	}
}

func TestG1AffineMultiply(t *testing.T) {
	for i := 0; i != 100; i++ {
		a := new(G1).Random()
		b := new(G1Affine).FromProjective(a)
		curr := new(G1).Copy(G1Zero)
		for j := 0; j != testStdIters; j++ {
			result := new(G1).MultiplyAffine(b, big.NewInt(int64(j)))
			if !G1Equal(result, curr) {
				t.Fatal("Multiplication does not match repeated addition")
			}
			curr.Add(curr, a)
		}
	}
}

func TestG1AffineHash(t *testing.T) {
	hashes := []*G1Affine{}
	for i := 0; i != testFewIters; i++ {
		buffer := make([]byte, 128)
		if _, err := rand.Read(buffer); err != nil {
			t.Fatal(err)
		}
		a := new(G1Affine).Hash(buffer)
		b := new(G1Affine).Hash(buffer)
		if !G1AffineEqual(a, b) {
			t.Fatal("Hash not deterministic")
		}
		for _, hash := range hashes {
			if G1AffineEqual(a, hash) {
				t.Fatal("Hash not collision-resistant")
			}
		}
		hashes = append(hashes, a)
	}
}

func TestG2Zero(t *testing.T) {
	a := new(G2Affine).Copy(G2ZeroAffine)
	b := new(G2).FromAffine(a)
	c := new(G2Affine).FromProjective(b)
	if !G2AffineEqual(a, c) {
		t.Fatal("Zero not copied/converted correctly")
	}
}

func TestG2AffineConversion(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G2).Random()
		b := new(G2Affine).FromProjective(a)
		c := new(G2).FromAffine(b)
		if !G2Equal(a, c) {
			t.Fatal("Converting to affine and back resulted in different element")
		}
	}
}

func TestG2Double(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G2).Random()
		b := new(G2).Double(a)
		c := new(G2).Copy(a)
		a.Add(a, c)
		if !G2Equal(a, b) {
			t.Fatal("Double does not match self-addition")
		}
	}
}

func TestG2AffineDouble(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G2).Random()
		b := new(G2).Double(a)
		c := new(G2Affine).FromProjective(a)
		a.AddMixed(a, c)
		if !G2Equal(a, b) {
			t.Fatal("Double does not match affine self-addition")
		}
	}
}

func TestG2Negate(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G2).Random()
		b := new(G2).Negate(a)
		a.Add(a, b)
		if !G2Equal(a, G2Zero) {
			t.Fatal("Element plus negation is not zero")
		}
	}
}

func TestG2AffineNegate(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a := new(G2).Random()
		b := new(G2Affine).FromProjective(a)
		b.Negate(b)
		a.AddMixed(a, b)
		if !G2Equal(a, G2Zero) {
			t.Fatal("Element plus negation is not zero")
		}
	}
}

func TestG2Multiply(t *testing.T) {
	for i := 0; i != 100; i++ {
		a := new(G2).Random()
		curr := new(G2).Copy(G2Zero)
		for j := 0; j != testStdIters; j++ {
			result := new(G2).Multiply(a, big.NewInt(int64(j)))
			if !G2Equal(result, curr) {
				t.Fatal("Multiplication does not match repeated addition")
			}
			curr.Add(curr, a)
		}
	}
}

func TestG2AffineMultiply(t *testing.T) {
	for i := 0; i != 100; i++ {
		a := new(G2).Random()
		b := new(G2Affine).FromProjective(a)
		curr := new(G2).Copy(G2Zero)
		for j := 0; j != testStdIters; j++ {
			result := new(G2).MultiplyAffine(b, big.NewInt(int64(j)))
			if !G2Equal(result, curr) {
				t.Fatal("Multiplication does not match repeated addition")
			}
			curr.Add(curr, a)
		}
	}
}

func TestG2AffineHash(t *testing.T) {
	hashes := []*G2Affine{}
	for i := 0; i != testFewIters; i++ {
		buffer := make([]byte, 128)
		if _, err := rand.Read(buffer); err != nil {
			t.Fatal(err)
		}
		a := new(G2Affine).Hash(buffer)
		b := new(G2Affine).Hash(buffer)
		if !G2AffineEqual(a, b) {
			t.Fatal("Hash not deterministic")
		}
		for _, hash := range hashes {
			if G2AffineEqual(a, hash) {
				t.Fatal("Hash not collision-resistant")
			}
		}
		hashes = append(hashes, a)
	}
}

func TestGTRandom(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a, _ := new(GT).Random(GTGenerator)
		b, s := new(GT).Random(a)
		c := new(GT).Multiply(a, s)
		if !GTEqual(b, c) {
			t.Fatal("Random GT element does not match base and returned scalar")
		}
	}
}

func TestGTDouble(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a, _ := new(GT).Random(GTGenerator)
		b := new(GT).Double(a)
		c := new(GT).Copy(a)
		a.Add(a, c)
		if !GTEqual(a, b) {
			t.Fatal("Double does not match self-addition")
		}
	}
}

func TestGTNegate(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		a, _ := new(GT).Random(GTGenerator)
		b := new(GT).Negate(a)
		a.Add(a, b)
		if !GTEqual(a, GTZero) {
			t.Fatal("Element plus negation is not zero")
		}
	}
}

func TestGTMultiply(t *testing.T) {
	for i := 0; i != 100; i++ {
		a, _ := new(GT).Random(GTGenerator)
		curr := new(GT).Copy(GTZero)
		for j := 0; j != testStdIters; j++ {
			result := new(GT).Multiply(a, big.NewInt(int64(j)))
			if !GTEqual(result, curr) {
				t.Fatal("Multiplication does not match repeated addition")
			}
			curr.Add(curr, a)
		}
	}
}

func TestGeneratorBilinearity(t *testing.T) {
	gtgen := new(GT).Pairing(G1GeneratorAffine, G2GeneratorAffine)
	if !GTEqual(gtgen, GTGenerator) {
		t.Fatal("Found counterexample to bilinearity")
	}
}

func TestBilinearity(t *testing.T) {
	for i := 0; i != testFewIters; i++ {
		a := new(G1).Random()
		b := new(G2).Random()

		x := cryptutils.RandomZp(new(big.Int))
		y := cryptutils.RandomZp(new(big.Int))

		xa := new(G1).Multiply(a, x)
		yb := new(G2).Multiply(b, y)

		eab := new(GT).Pairing(new(G1Affine).FromProjective(a), new(G2Affine).FromProjective(b))
		xyeab := new(GT).Multiply(eab, y)
		xyeab.Multiply(xyeab, x)
		exayb := new(GT).Pairing(new(G1Affine).FromProjective(xa), new(G2Affine).FromProjective(yb))

		if !GTEqual(xyeab, exayb) {
			t.Fatal("Found counterexample to bilinearity")
		}
	}
}

func TestPreparedPairing(t *testing.T) {
	for i := 0; i != testFewIters; i++ {
		a := new(G1Affine).FromProjective(new(G1).Random())
		b := new(G2Affine).FromProjective(new(G2).Random())
		bp := new(G2Prepared).Prepare(b)

		eab1 := new(GT).Pairing(a, b)
		eab2 := new(GT).PreparedPairing(a, bp)

		if !GTEqual(eab1, eab2) {
			t.Fatal("Prepared pairing is incorrect")
		}
	}
}

func TestPairingSum(t *testing.T) {
	for i := 0; i != testFewIters; i++ {
		a := new(G1Affine).FromProjective(new(G1).Random())
		b := new(G2Affine).FromProjective(new(G2).Random())

		c := new(G1Affine).FromProjective(new(G1).Random())
		d := new(G2Affine).FromProjective(new(G2).Random())

		w := new(G1Affine).FromProjective(new(G1).Random())
		x := new(G2Prepared).Prepare(new(G2Affine).FromProjective(new(G2).Random()))

		y := new(G1Affine).FromProjective(new(G1).Random())
		z := new(G2Prepared).Prepare(new(G2Affine).FromProjective(new(G2).Random()))

		eab := new(GT).Pairing(a, b)
		ecd := new(GT).Pairing(c, d)
		exy := new(GT).PreparedPairing(w, x)
		eyz := new(GT).PreparedPairing(y, z)
		eabecdexyeyz := new(GT).Add(new(GT).Add(eab, ecd), new(GT).Add(exy, eyz))

		pairsum := new(GT).PairingSum([]*G1Affine{a, c}, []*G2Affine{b, d}, []*G1Affine{w, y}, []*G2Prepared{x, z})

		if !GTEqual(eabecdexyeyz, pairsum) {
			t.Fatal("Found counterexample to bilinearity")
		}
	}
}

func BenchmarkG1Add(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		a := new(G1).Random()
		c := new(G1).Random()
		d := new(G1)
		b.StartTimer()
		d.Add(a, c)
		b.StopTimer()
	}
}

func BenchmarkG1AddMixed(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		a := new(G1).Random()
		c := new(G1Affine).FromProjective(new(G1).Random())
		d := new(G1)
		b.StartTimer()
		d.AddMixed(a, c)
		b.StopTimer()
	}
}

func BenchmarkG1Multiply(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a := new(G1).Random()
		c := new(G1)
		s := cryptutils.RandomZp(new(big.Int))
		b.StartTimer()
		c.Multiply(a, s)
		b.StopTimer()
	}
}

func BenchmarkG2Add(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		a := new(G2).Random()
		c := new(G2).Random()
		d := new(G2)
		b.StartTimer()
		d.Add(a, c)
		b.StopTimer()
	}
}

func BenchmarkG2AddMixed(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		a := new(G2).Random()
		c := new(G2Affine).FromProjective(new(G2).Random())
		d := new(G2)
		b.StartTimer()
		d.AddMixed(a, c)
		b.StopTimer()
	}
}

func BenchmarkG2Multiply(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a := new(G2).Random()
		c := new(G2)
		s := cryptutils.RandomZp(new(big.Int))
		b.StartTimer()
		c.Multiply(a, s)
		b.StopTimer()
	}
}

func BenchmarkGTAdd(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		a, _ := new(GT).Random(GTGenerator)
		c, _ := new(GT).Random(GTGenerator)
		d := new(GT)
		b.StartTimer()
		d.Add(a, c)
		b.StopTimer()
	}
}

func BenchmarkGTMultiply(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a, _ := new(GT).Random(GTGenerator)
		c := new(GT)
		s := cryptutils.RandomZp(new(big.Int))
		b.StartTimer()
		c.Multiply(a, s)
		b.StopTimer()
	}
}

func BenchmarkGTRandom(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a, _ := new(GT).Random(GTGenerator)
		c := new(GT)
		b.StartTimer()
		_, _ = c.Random(a)
		b.StopTimer()
	}
}

func BenchmarkPairing(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a := new(G1Affine).FromProjective(new(G1).Random())
		c := new(G2Affine).FromProjective(new(G2).Random())
		eac := new(GT)
		b.StartTimer()
		eac.Pairing(a, c)
		b.StopTimer()
	}
}

func BenchmarkPreparedPairing(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a := new(G1Affine).FromProjective(new(G1).Random())
		c := new(G2Affine).FromProjective(new(G2).Random())
		cp := new(G2Prepared).Prepare(c)
		eac := new(GT)
		b.StartTimer()
		eac.PreparedPairing(a, cp)
		b.StopTimer()
	}
}

func BenchmarkPairingSum4(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		a := new(G1Affine).FromProjective(new(G1).Random())
		c := new(G2Affine).FromProjective(new(G2).Random())
		d := new(G1Affine).FromProjective(new(G1).Random())
		f := new(G2Affine).FromProjective(new(G2).Random())
		g := new(G1Affine).FromProjective(new(G1).Random())
		h := new(G2Affine).FromProjective(new(G2).Random())
		k := new(G1Affine).FromProjective(new(G1).Random())
		m := new(G2Affine).FromProjective(new(G2).Random())
		eac := new(GT)
		b.StartTimer()
		eac.PairingSum([]*G1Affine{a, d, g, k}, []*G2Affine{c, f, h, m}, nil, nil)
		b.StopTimer()
	}
}
