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

package lqibe

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	idbytes := []byte{1, 2, 3}
	id := new(ID).Hash(idbytes)

	pp, msk := Setup()
	sk := KeyGen(pp, msk, id)

	symm1 := make([]byte, 32)
	c := Encrypt(symm1, pp, id)

	symm2 := make([]byte, 32)
	Decrypt(c, sk, id, symm2)

	if !bytes.Equal(symm1, symm2) {
		t.Fatal("Original and decrypted symmetric keys differ")
	}
}

func TestBadKey(t *testing.T) {
	id1bytes := []byte{1, 2, 3}
	id1 := new(ID).Hash(id1bytes)

	id2bytes := []byte{1, 2, 3, 4}
	id2 := new(ID).Hash(id2bytes)

	pp, msk := Setup()
	sk := KeyGen(pp, msk, id1)

	symm1 := make([]byte, 32)
	c := Encrypt(symm1, pp, id2)

	symm2 := make([]byte, 32)
	Decrypt(c, sk, id1, symm2)
	if bytes.Equal(symm1, symm2) {
		t.Fatal("Correctly decrypted with bad key")
	}

	Decrypt(c, sk, id2, symm2)
	if bytes.Equal(symm1, symm2) {
		t.Fatal("Correctly decrypted with bad key")
	}
}
