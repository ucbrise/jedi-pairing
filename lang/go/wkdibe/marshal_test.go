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

const MarshalledCiphertext = "\x41\x67\x79\x55\xa0\x5d\x74\x31\xf5\x93\x72\x0b\x3a\xf3\xcd\x29\xf6\x90\xfb\x6c\xba\xd0\x53\xb0\x6e\x30\xcf\x26\xaa\xbc\x06\xca\xb9\x96\x11\x88\x20\x2e\x64\x39\x05\xa3\xaa\xf6\x91\x12\x24\x02\xbb\xa3\x84\x32\x95\x6c\x80\x38\x57\xa2\x97\x5d\xab\x38\x7a\xc7\x6e\x8e\xb9\xf9\xdc\xcb\x3d\x79\x7d\x4b\xc3\x20\xd2\x2f\x1d\xe5\x92\xf3\x73\x13\x8e\x78\x64\x4a\x65\xd3\x13\x6e\x1e\x69\x92\x15\x1b\x87\x23\xf0\xc0\x87\x50\x05\xce\x0a\xb6\x16\x80\x78\xa9\x32\x57\xbc\x47\x53\x4f\xcc\x66\x78\x12\x93\xc3\xdc\xa4\x9e\x0d\x09\x51\xf0\x8e\x3a\xd7\x7f\x93\xb8\xf5\xf7\x7c\x6a\x8e\x05\x24\x18\xaa\x87\xdb\xa3\xef\x56\xc7\xcc\x19\x28\x07\x45\x21\x1e\x30\xb5\x85\x56\x23\x86\x95\x54\xe0\xae\xe5\x62\x8b\xe9\x10\x1b\x8d\x73\xf7\xcb\x4a\x55\xc7\xac\xc3\x7c\xed\xfd\x47\xe1\x5d\x5d\xff\x16\x23\x83\xaf\x79\x85\x6b\x64\xfd\xc2\xab\x6b\xb9\x9d\x09\x1c\x39\x1d\xa8\x08\xb3\x86\x46\x5b\xce\x29\x5b\xf5\x12\x62\x3c\x87\x20\x7b\xf3\x39\xdb\x25\x6f\xf8\x50\x3e\xcd\x5f\x4e\xa1\xbc\x5c\x04\x41\xc4\xca\xc9\xe6\x98\x7b\xc2\xe9\xec\xfd\x45\x09\x3f\xbe\xe9\x0f\xa7\xbf\x9f\xbd\x3d\x33\x09\x66\x75\xdc\xc2\x93\xbf\x05\x3e\x60\x17\xa3\x52\xaf\x5d\xe8\x4c\x77\xf5\x4a\x79\x0c\xd2\xd5\x04\x10\xe7\x23\x07\x5c\x46\x83\xdb\xe9\xb2\xfb\x0a\xd1\xf2\x4e\x18\xdc\x49\xe4\x4b\x61\xb9\x56\x94\x03\x15\xca\x96\x97\xa6\x7c\xe3\x4f\xf9\x54\xa3\x55\x9b\xbd\x1e\x5a\xb5\xd9\x67\xf6\xc1\x27\x06\x2c\xf8\x08\x98\xee\x92\x1b\x41\x0e\xef\xef\x7c\xa5\xcd\xf7\x0a\xb7\x92\xb3\xe8\x8a\x8e\x01\x37\x8d\xb4\xaf\x28\xc0\x27\xee\x23\xb8\x73\xfd\xe6\x0a\x7f\xc6\x56\xef\x3e\x67\x57\xb4\x86\xc7\x14\x14\xc4\xa7\x05\x4b\xb1\x2d\xce\x92\x78\xac\x20\x9e\xd4\x39\x01\xc1\x44\x24\xe8\xd8\xf0\x3f\xac\xe6\x0c\xda\xb9\x1b\x89\x1f\xa0\x14\x9e\x42\xc1\x3f\x23\x29\x5e\x3d\x2c\x75\x22\x9c\x6d\xd5\x06\xef\xfa\xd8\x76\x28\x12\x27\xf0\x92\x9d\x2b\x18\xdb\xf8\x63\xf1\x72\xc6\x21\x20\xea\x11\x30\xac\x4f\xd6\xce\xfc\x86\x11\x88\x44\xeb\x8b\xe0\xf2\x0d\x58\x6c\x1a\x13\x88\x6d\x7c\xa3\x72\x02\x06\x72\xe8\x82\x4b\x3e\x37\xa0\x74\x6e\x0b\xb4\xfe\xac\x17\xe4\x12\x57\x66\x97\x5d\xc8\xa2\x03\x58\xa9\x41\x55\xb7\x5c\x00\x84\xcc\xa5\x56\x80\x2b\x91\xbd\x29\x00\xc6\x68\xfa\x87\x12\x11\xb5\x11\x9e\xc6\xb4\x7c\x4f\x40\x47\xbe\xcf\x9c\x64\xfd\xa6\x24\xc3\x0d\x94\xd3\xbf\x53\xeb\xcf\xf0\x24\x4a\xf6\x82\x0d\xb0\xef\xd9\x93\xa6\x34\xd2\x13\xcb\xe9\x48\xfb\x0f\xa6\x9b\xe1\x61\xa0\xdb\x18\x8e\x2a\x04\x58\x98\x0c\xe6\x1a\x0a\x38\x9d\x70\x35\xc0\x09\xdf\x99\x67\x96\x43\x41\x3a\x53\xa5\x65\x03\x0d\x02\x1c\x88\x75\xff\xc1\xb6\xba\x5f\x34\x77\x02\x1f\xa7\x46\x95\x61\x70\xd5\x25\xc8\x06\x54\x47\xd4\x56\x1a\x12\x6c\xf8\x05\x9c\x49\xd1\xd6\x27\x22\xcd\x91\x88\x48\x60\xe9\xd5\x15\x8c\xcc\xf7\xa1\xcf\x6c\xde\x97\xda\x01\x12\x26\x44\x34\x56\xa2\xbc\xff\x98\x37\x21\xba\x52\xf8\xa2\x37\x12\xf0\xf7\xec\xd8\x75\xe6\x46\xe0\xf6\x98\x26\x14\x6f\x48\x7b\xff\x8f\xa3\x0e\x7e\xd5\xc3\x9e\x48\x63\x70\xb1\x37\x9f\x7e\x9e\x37\xfd\x3c\x17\x1a\x64\xd1\xdd\xd5\x21\x91\x35\xec\xd2"

func TestCiphertextUnaligned(t *testing.T) {
	buffer := make([]byte, 2*len(MarshalledCiphertext))
	copy(buffer[1:len(MarshalledCiphertext)+1], MarshalledCiphertext)

	c := new(Ciphertext)
	c.Unmarshal(buffer, true, true)
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

	params, key := Setup(numAttrs, true)
	privkey := KeyGen(params, key, attrs)
	privkeybytes := privkey.Marshal(compressed)
	privkey2 := new(SecretKey)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		privkey2.Unmarshal(privkeybytes, compressed, checked)
	}
	b.StopTimer()
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
