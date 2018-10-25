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

package wkdibe

import (
	"bytes"
	"math/big"
	"testing"
)

func HelperTestEncryptionMarshalling(t *testing.T, compressed bool) {
	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key := Setup(10, false)

	parambytes := params.Marshal(compressed)
	params = new(Params)
	ok := params.Unmarshal(parambytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal Params")
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := Encrypt(message, params, attrs1)

	ciphertextbytes := ciphertext.Marshal(compressed)
	ciphertext = new(Ciphertext)
	ok = ciphertext.Unmarshal(ciphertextbytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal Ciphertext")
	}

	privkey := KeyGen(params, key, attrs1)

	privkeybytes := privkey.Marshal(compressed)
	privkey = new(SecretKey)
	ok = privkey.Unmarshal(privkeybytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal private key")
	}

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(ciphertext, privkey)
	if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func HelperTestSignatureMarshalling(t *testing.T, compressed bool) {
	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key := Setup(10, true)

	parambytes := params.Marshal(compressed)
	params = new(Params)
	ok := params.Unmarshal(parambytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal Params (#1)")
	}

	// Come up with a message to encrypt
	message := NewSignatureMessage(t)

	privkey := KeyGen(params, key, attrs1)

	privkeybytes := privkey.Marshal(compressed)
	privkey = new(SecretKey)
	ok = privkey.Unmarshal(privkeybytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal private key (#1)")
	}

	// Some additional marshalling checks on params
	parambytes = params.Marshal(compressed)
	ok = params.Unmarshal(parambytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal Params (#2)")
	}
	params2 := new(Params)
	ok = params2.Unmarshal(parambytes[:len(parambytes)-1], compressed, true)
	if ok {
		t.Fatal("Unmarshalled bad Params")
	}

	// Some additional marshalling checks on privkey
	privkeybytes = privkey.Marshal(compressed)
	ok = privkey.Unmarshal(privkeybytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal private key (#2)")
	}
	privkey2 := new(SecretKey)
	ok = privkey2.Unmarshal(privkeybytes[:len(privkeybytes)-1], compressed, true)
	if ok {
		t.Fatal("Unmarshalled bad private key")
	}

	// Sign a message under the top level public key
	signature := Sign(params, privkey, attrs1, message)

	signaturebytes := signature.Marshal(compressed)
	signature = new(Signature)
	ok = signature.Unmarshal(signaturebytes, compressed, true)
	if !ok {
		t.Fatal("Could not unmarshal Signature")
	}

	// Verify the signature
	correct := Verify(params, attrs1, signature, message)
	if !correct {
		t.Fatal("Signature was not successfully verified")
	}
}

func TestEncryptionMarshallingCompressed(t *testing.T) {
	HelperTestEncryptionMarshalling(t, true)
}

func TestEncryptionMarshallingUncompressed(t *testing.T) {
	HelperTestEncryptionMarshalling(t, false)
}

func TestSignatureMarshallingCompressed(t *testing.T) {
	HelperTestSignatureMarshalling(t, true)
}

func TestSignatureMarshallingUncompressed(t *testing.T) {
	HelperTestSignatureMarshalling(t, false)
}

func HelperBenchmarkMarshalSecretKey(b *testing.B, numAttrs int, compressed bool) {
	b.StopTimer()
	attrs := make(AttributeList)

	for i := 0; i < b.N; i++ {
		params, key := Setup(numAttrs, true)
		privkey := KeyGen(params, key, attrs)

		b.StartTimer()
		_ = privkey.Marshal(compressed)
		b.StopTimer()
	}
}

func HelperBenchmarkUnmarshalSecretKey(b *testing.B, numAttrs int, compressed bool, checked bool) {
	b.StopTimer()
	attrs := make(AttributeList)

	for i := 0; i < b.N; i++ {
		params, key := Setup(numAttrs, true)
		privkey := KeyGen(params, key, attrs)
		privkeybytes := privkey.Marshal(compressed)
		privkey2 := new(SecretKey)

		b.StartTimer()
		privkey2.Unmarshal(privkeybytes, compressed, checked)
		b.StopTimer()
	}
}

// func BenchmarkMarshalSecretKey5Compressed(b *testing.B) {
// 	HelperBenchmarkMarshalSecretKey(b, 5, true)
// }
//
// func BenchmarkMarshalSecretKey10Compressed(b *testing.B) {
// 	HelperBenchmarkMarshalSecretKey(b, 10, true)
// }
//
// func BenchmarkMarshalSecretKey15Compressed(b *testing.B) {
// 	HelperBenchmarkMarshalSecretKey(b, 15, true)
// }
//
// func BenchmarkMarshalSecretKey20Compressed(b *testing.B) {
// 	HelperBenchmarkMarshalSecretKey(b, 20, true)
// }

func BenchmarkUnmarshalSecretKey5CompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 5, true, true)
}

func BenchmarkUnmarshalSecretKey10CompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 10, true, true)
}

func BenchmarkUnmarshalSecretKey15CompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 15, true, true)
}

func BenchmarkUnmarshalSecretKey20CompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 20, true, true)
}

func BenchmarkUnmarshalSecretKey5UncompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 5, false, true)
}

func BenchmarkUnmarshalSecretKey10UncompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 10, false, true)
}

func BenchmarkUnmarshalSecretKey15UncompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 15, false, true)
}

func BenchmarkUnmarshalSecretKey20UncompressedChecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 20, false, true)
}

func BenchmarkUnmarshalSecretKey5CompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 5, true, false)
}

func BenchmarkUnmarshalSecretKey10CompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 10, true, false)
}

func BenchmarkUnmarshalSecretKey15CompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 15, true, false)
}

func BenchmarkUnmarshalSecretKey20CompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 20, true, false)
}

func BenchmarkUnmarshalSecretKey5UncompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 5, false, false)
}

func BenchmarkUnmarshalSecretKey10UncompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 10, false, false)
}

func BenchmarkUnmarshalSecretKey15UncompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 15, false, false)
}

func BenchmarkUnmarshalSecretKey20UncompressedUnchecked(b *testing.B) {
	HelperBenchmarkUnmarshalSecretKey(b, 20, false, false)
}
