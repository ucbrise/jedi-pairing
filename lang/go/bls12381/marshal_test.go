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
	"testing"
)

func TestMarshalG1(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g := new(G1Affine).FromProjective(new(G1).Random())

		bufc := make([]byte, G1MarshalledCompressedSize)
		bufu := make([]byte, G1MarshalledUncompressedSize)
		if bufc = g.Marshal(bufc, true); bufc == nil {
			t.Fatal("Compressed marshal failed")
		}
		if bufu = g.Marshal(bufu, false); bufu == nil {
			t.Fatal("Uncompressed marshal failed")
		}

		hc := new(G1Affine)
		hc = hc.Unmarshal(bufc, true, true)
		if !G1AffineEqual(g, hc) {
			t.Fatal("Compressed marshal/unmarshal incorrect")
		}

		hu := new(G1Affine)
		hu = hu.Unmarshal(bufu, false, true)
		if !G1AffineEqual(g, hu) {
			t.Fatal("Uncompressed marshal/unmarshal incorrect")
		}
	}
}

func TestMarshalG1Nil(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g := new(G1Affine).FromProjective(new(G1).Random())
		if g.Marshal(nil, true) != nil || g.Marshal(nil, false) != nil {
			t.Fatal("Marshalling into nil buffer succeeded")
		}
		if g.Unmarshal(nil, true, false) != nil || g.Unmarshal(nil, false, false) != nil {
			t.Fatal("Unmarshalling from nil buffer succeeded")
		}
	}
}

func TestMarshalG2(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g := new(G2Affine).FromProjective(new(G2).Random())

		bufc := make([]byte, G2MarshalledCompressedSize)
		bufu := make([]byte, G2MarshalledUncompressedSize)
		if bufc = g.Marshal(bufc, true); bufc == nil {
			t.Fatal("Compressed marshal failed")
		}
		if bufu = g.Marshal(bufu, false); bufu == nil {
			t.Fatal("Uncompressed marshal failed")
		}

		hc := new(G2Affine)
		hc = hc.Unmarshal(bufc, true, true)
		if !G2AffineEqual(g, hc) {
			t.Fatal("Compressed marshal/unmarshal incorrect")
		}

		hu := new(G2Affine)
		hu = hu.Unmarshal(bufu, false, true)
		if !G2AffineEqual(g, hu) {
			t.Fatal("Uncompressed marshal/unmarshal incorrect")
		}
	}
}

func TestMarshalG2Nil(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g := new(G2Affine).FromProjective(new(G2).Random())
		if g.Marshal(nil, true) != nil || g.Marshal(nil, false) != nil {
			t.Fatal("Marshalling into nil buffer succeeded")
		}
		if g.Unmarshal(nil, true, false) != nil || g.Unmarshal(nil, false, false) != nil {
			t.Fatal("Unmarshalling from nil buffer succeeded")
		}
	}
}

func TestMarshalGTNil(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g, _ := new(GT).Random(GTGenerator)
		if g.Marshal(nil) != nil {
			t.Fatal("Marshalling into nil buffer succeeded")
		}
		if g.Unmarshal(nil) != nil {
			t.Fatal("Unmarshalling from nil buffer succeeded")
		}
	}
}

func TestMarshalGT(t *testing.T) {
	for i := 0; i != testStdIters; i++ {
		g, _ := new(GT).Random(GTGenerator)

		buf := make([]byte, GTMarshalledSize)
		if buf = g.Marshal(buf); buf == nil {
			t.Fatal("Marshal failed")
		}

		h := new(GT)
		h = h.Unmarshal(buf)
		if !GTEqual(g, h) {
			t.Fatal("Marshal/unmarshal incorrect")
		}
	}
}

func benchmarkG1Marshal(b *testing.B, compressed bool) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	var size int
	if compressed {
		size = G1MarshalledCompressedSize
	} else {
		size = G1MarshalledUncompressedSize
	}
	for i := 0; i < b.N; i++ {
		g := new(G1Affine).FromProjective(new(G1).Random())
		buf := make([]byte, size)
		b.StartTimer()
		g.Marshal(buf, compressed)
		b.StopTimer()
	}
}

func BenchmarkG1MarshalCompressed(b *testing.B) {
	benchmarkG1Marshal(b, true)
}

func BenchmarkG1MarshalUncompressed(b *testing.B) {
	benchmarkG1Marshal(b, false)
}

func benchmarkG1Unmarshal(b *testing.B, compressed bool, checked bool) {
	b.StopTimer()
	if !compressed && !checked && testing.Short() {
		b.SkipNow()
	}
	var size int
	if compressed {
		size = G1MarshalledCompressedSize
	} else {
		size = G1MarshalledUncompressedSize
	}
	for i := 0; i < b.N; i++ {
		g := new(G1Affine).FromProjective(new(G1).Random())
		buf := make([]byte, size)
		g.Marshal(buf, compressed)
		h := new(G1Affine)
		b.StartTimer()
		h.Unmarshal(buf, compressed, checked)
		b.StopTimer()
	}
}

func BenchmarkG1UnmarshalCompressedChecked(b *testing.B) {
	benchmarkG1Unmarshal(b, true, true)
}

func BenchmarkG1UnmarshalUncompressedChecked(b *testing.B) {
	benchmarkG1Unmarshal(b, false, true)
}

func BenchmarkG1UnmarshalCompressedUnchecked(b *testing.B) {
	benchmarkG1Unmarshal(b, true, false)
}

func BenchmarkG1UnmarshalUncompressedUnchecked(b *testing.B) {
	benchmarkG1Unmarshal(b, false, false)
}

func benchmarkG2Marshal(b *testing.B, compressed bool) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	var size int
	if compressed {
		size = G2MarshalledCompressedSize
	} else {
		size = G2MarshalledUncompressedSize
	}
	for i := 0; i < b.N; i++ {
		g := new(G2Affine).FromProjective(new(G2).Random())
		buf := make([]byte, size)
		b.StartTimer()
		g.Marshal(buf, compressed)
		b.StopTimer()
	}
}

func BenchmarkG2MarshalCompressed(b *testing.B) {
	benchmarkG2Marshal(b, true)
}

func BenchmarkG2MarshalUncompressed(b *testing.B) {
	benchmarkG2Marshal(b, false)
}

func benchmarkG2Unmarshal(b *testing.B, compressed bool, checked bool) {
	b.StopTimer()
	if !compressed && !checked && testing.Short() {
		b.SkipNow()
	}
	var size int
	if compressed {
		size = G2MarshalledCompressedSize
	} else {
		size = G2MarshalledUncompressedSize
	}
	for i := 0; i < b.N; i++ {
		g := new(G2Affine).FromProjective(new(G2).Random())
		buf := make([]byte, size)
		g.Marshal(buf, compressed)
		h := new(G2Affine)
		b.StartTimer()
		h.Unmarshal(buf, compressed, checked)
		b.StopTimer()
	}
}

func BenchmarkG2UnmarshalCompressedChecked(b *testing.B) {
	benchmarkG2Unmarshal(b, true, true)
}

func BenchmarkG2UnmarshalUncompressedChecked(b *testing.B) {
	benchmarkG2Unmarshal(b, false, true)
}

func BenchmarkG2UnmarshalCompressedUnchecked(b *testing.B) {
	benchmarkG2Unmarshal(b, true, false)
}

func BenchmarkG2UnmarshalUncompressedUnchecked(b *testing.B) {
	benchmarkG2Unmarshal(b, false, false)
}

func BenchmarkGTMarshal(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		g, _ := new(GT).Random(GTGenerator)
		buf := make([]byte, GTMarshalledSize)
		b.StartTimer()
		g.Marshal(buf)
		b.StopTimer()
	}
}

func BenchmarkGTUnmarshal(b *testing.B) {
	b.StopTimer()
	if testing.Short() {
		b.SkipNow()
	}
	for i := 0; i < b.N; i++ {
		g, _ := new(GT).Random(GTGenerator)
		buf := make([]byte, GTMarshalledSize)
		g.Marshal(buf)
		h := new(GT)
		b.StartTimer()
		h.Unmarshal(buf)
		b.StopTimer()
	}
}
