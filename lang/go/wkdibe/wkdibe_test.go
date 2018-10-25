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
	"crypto/rand"
	"math/big"
	"testing"
)

func NewMessage() *Encryptable {
	return new(Encryptable).Random()
}

func NewSignatureMessage(t *testing.T) *Signable {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	return new(Signable).Hash(buffer)
}

func NewSignatureMessageBenchmark(b *testing.B) *Signable {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		b.Fatal(err)
	}
	return new(Signable).Hash(buffer)
}

func encryptHelper(t *testing.T, params *Params, attrs AttributeList, message *Encryptable) *Ciphertext {
	return Encrypt(message, params, attrs)
}

func encryptPreparedHelper(t *testing.T, params *Params, precomputed *PreparedAttributeList, message *Encryptable) *Ciphertext {
	return EncryptPrepared(message, params, precomputed)
}

func verifyHelper(t *testing.T, params *Params, attrs AttributeList, signature *Signature, message *Signable) {
	correct := Verify(params, attrs, signature, message)
	if !correct {
		t.Fatal("Signature is invalid")
	}
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey *MasterKey, attrs AttributeList) *SecretKey {
	// Generate key for the single attributes
	return KeyGen(params, masterkey, attrs)
}

func qualifyHelper(t *testing.T, params *Params, key *SecretKey, attrs AttributeList) *SecretKey {
	return QualifyKey(params, key, attrs)
}

func decryptAndCheckHelper(t *testing.T, key *SecretKey, ciphertext *Ciphertext, message *Encryptable) {
	decrypted := Decrypt(ciphertext, key)
	if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func signHelper(t *testing.T, params *Params, key *SecretKey, attrs AttributeList, message *Signable) *Signature {
	return Sign(params, key, attrs, message)
}

func attributeFromMasterHelper(t *testing.T, attrs AttributeList) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, attrs)

	decryptAndCheckHelper(t, key, ciphertext, message)
}

func attributeFromMasterSignatureHelper(t *testing.T, attrs AttributeList) {
	// Set up parameters
	params, masterkey := Setup(10, true)

	// Come up with a message to sign
	message := NewSignatureMessage(t)

	// Generate key for the attributes
	key := genFromMasterHelper(t, params, masterkey, attrs)

	// Sign the message
	signature := signHelper(t, params, key, attrs, message)

	// Verify the signature
	verifyHelper(t, params, attrs, signature, message)
}

func TestSingleAttributeEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{0: big.NewInt(1)})
}

func TestSingleSparseAttributeEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(1)})
}

func TestMultipleSparseAttributesEncryption(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(1), 8: big.NewInt(123)})
}

func TestSingleAttributeSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{0: big.NewInt(1)})
}

func TestSingleSparseAttributeSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{1: big.NewInt(1)})
}

func TestMultipleSparseAttributesSignature(t *testing.T) {
	attributeFromMasterSignatureHelper(t, AttributeList{1: big.NewInt(1), 8: big.NewInt(123)})
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := qualifyHelper(t, params, key1, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestAdjustPrepared1(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs1 := AttributeList{2: big.NewInt(4), 5: big.NewInt(8)}
	attrs2 := AttributeList{3: big.NewInt(4), 5: big.NewInt(8), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	prepared := PrepareAttributeList(params, attrs1)
	AdjustPreparedAttributeList(prepared, params, attrs1, attrs2)
	ciphertext := encryptPreparedHelper(t, params, prepared, message)

	// Generate key in two steps
	key := genFromMasterHelper(t, params, masterkey, attrs2)

	decryptAndCheckHelper(t, key, ciphertext, message)
}

func TestAdjustPrepared2(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs1 := AttributeList{2: big.NewInt(4), 5: big.NewInt(8)}
	attrs2 := AttributeList{3: big.NewInt(4), 5: big.NewInt(9), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	prepared := PrepareAttributeList(params, attrs2)
	AdjustPreparedAttributeList(prepared, params, attrs2, attrs1)
	ciphertext := encryptPreparedHelper(t, params, prepared, message)

	// Generate key in two steps
	key := genFromMasterHelper(t, params, masterkey, attrs1)

	decryptAndCheckHelper(t, key, ciphertext, message)
}

func TestNonDelegableQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := NonDelegableQualifyKey(params, key1, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestDecryptWithMaster(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	decrypted := DecryptWithMaster(ciphertext, masterkey)
	if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestNonDelegableKeyGen(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in one step
	key2 := NonDelegableKeyGen(params, masterkey, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestPartialDelegation(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, false)

	attrs1 := AttributeList{2: big.NewInt(4), 6: nil}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}
	attrs3 := AttributeList{2: big.NewInt(4), 6: big.NewInt(124)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)

	// This should work fine
	ciphertext := encryptHelper(t, params, attrs2, message)
	key2 := qualifyHelper(t, params, key1, attrs2)
	decryptAndCheckHelper(t, key2, ciphertext, message)

	// This should not work, because slot 6 is hidden
	ciphertext = encryptHelper(t, params, attrs3, message)
	key3 := qualifyHelper(t, params, key1, attrs3)
	decrypted := Decrypt(ciphertext, key3)
	if bytes.Equal(message.Bytes(), decrypted.Bytes()) {
		t.Fatal("Managed to fill hidden slot")
	}
}

func TestResampleKey(t *testing.T) {
	// Set up parameters
	params, masterkey := Setup(10, true)

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := ResampleKey(params, PrepareAttributeList(params, attrs1), key1, true)
	key3 := NonDelegableQualifyKey(params, key2, attrs2)

	decryptAndCheckHelper(t, key3, ciphertext, message)
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = Setup(20, true)
	}
}

func EncryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, _ := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewMessage()

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StartTimer()
		_ = Encrypt(message, params, attrs)
		b.StopTimer()
	}
}

func BenchmarkEncrypt_5(b *testing.B) {
	EncryptBenchmarkHelper(b, 5)
}

func BenchmarkEncrypt_10(b *testing.B) {
	EncryptBenchmarkHelper(b, 10)
}

func BenchmarkEncrypt_15(b *testing.B) {
	EncryptBenchmarkHelper(b, 15)
}

func BenchmarkEncrypt_20(b *testing.B) {
	EncryptBenchmarkHelper(b, 20)
}

func EncryptCachedBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, _ := Setup(20, true)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message := NewMessage()

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		precomputed := PrepareAttributeList(params, attrs)

		b.StartTimer()
		_ = EncryptPrepared(message, params, precomputed)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptCached_5(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 5)
}

func BenchmarkEncryptCached_10(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 10)
}

func BenchmarkEncryptCached_15(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 15)
}

func BenchmarkEncryptCached_20(b *testing.B) {
	EncryptCachedBenchmarkHelper(b, 20)
}

func DecryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message := NewMessage()

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, attrs)
		ciphertext := Encrypt(message, params, attrs)

		b.StartTimer()
		decrypted := Decrypt(ciphertext, key)
		b.StopTimer()

		if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecrypt_5(b *testing.B) {
	DecryptBenchmarkHelper(b, 5)
}

func BenchmarkDecrypt_10(b *testing.B) {
	DecryptBenchmarkHelper(b, 10)
}

func BenchmarkDecrypt_15(b *testing.B) {
	DecryptBenchmarkHelper(b, 15)
}

func BenchmarkDecrypt_20(b *testing.B) {
	DecryptBenchmarkHelper(b, 20)
}

func DecryptWithMasterBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewMessage()

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		ciphertext := Encrypt(message, params, attrs)

		b.StartTimer()
		decrypted := DecryptWithMaster(ciphertext, master)
		b.StopTimer()

		if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecryptWithMaster_5(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 5)
}

func BenchmarkDecryptWithMaster_10(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 10)
}

func BenchmarkDecryptWithMaster_15(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 15)
}

func BenchmarkDecryptWithMaster_20(b *testing.B) {
	DecryptWithMasterBenchmarkHelper(b, 20)
}

func NonDelegableQualifyKeyBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewMessage()

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		pseudomaster := KeyGen(params, master, AttributeList{})
		ciphertext := Encrypt(message, params, attrs)

		b.StartTimer()
		key := NonDelegableQualifyKey(params, pseudomaster, attrs)
		b.StopTimer()

		decrypted := Decrypt(ciphertext, key)
		if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkNonDelegableQualifyKey_5(b *testing.B) {
	NonDelegableQualifyKeyBenchmarkHelper(b, 5)
}

func BenchmarkNonDelegableQualifyKey_10(b *testing.B) {
	NonDelegableQualifyKeyBenchmarkHelper(b, 10)
}

func BenchmarkNonDelegableQualifyKey_15(b *testing.B) {
	NonDelegableQualifyKeyBenchmarkHelper(b, 15)
}

func BenchmarkNonDelegableQualifyKey_20(b *testing.B) {
	NonDelegableQualifyKeyBenchmarkHelper(b, 20)
}

func SignBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewSignatureMessageBenchmark(b)

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
		}

		key := KeyGen(params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		_ = Sign(params, key, attrs, message)
		b.StopTimer()
	}
}

func BenchmarkSign_5(b *testing.B) {
	SignBenchmarkHelper(b, 5)
}

func BenchmarkSign_10(b *testing.B) {
	SignBenchmarkHelper(b, 10)
}

func BenchmarkSign_15(b *testing.B) {
	SignBenchmarkHelper(b, 15)
}

func BenchmarkSign_20(b *testing.B) {
	SignBenchmarkHelper(b, 20)
}

func SignCachedBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewSignatureMessageBenchmark(b)

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, attrs)
		precomputed := PrepareAttributeList(params, attrs)

		b.StartTimer()
		_ = SignPrepared(params, key, nil, precomputed, message)
		b.StopTimer()
	}
}

func VerifyBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewSignatureMessageBenchmark(b)

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, attrs)
		signature := Sign(params, key, attrs, message)

		b.StartTimer()
		correct := Verify(params, attrs, signature, message)
		b.StopTimer()

		if !correct {
			b.Fatal("Signature is not valid")
		}
	}
}

func BenchmarkVerify_5(b *testing.B) {
	VerifyBenchmarkHelper(b, 5)
}

func BenchmarkVerify_10(b *testing.B) {
	VerifyBenchmarkHelper(b, 10)
}

func BenchmarkVerify_15(b *testing.B) {
	VerifyBenchmarkHelper(b, 15)
}

func BenchmarkVerify_20(b *testing.B) {
	VerifyBenchmarkHelper(b, 20)
}

func VerifyCachedBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		message := NewSignatureMessageBenchmark(b)

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, attrs)
		signature := Sign(params, key, attrs, message)

		precomputed := PrepareAttributeList(params, attrs)

		b.StartTimer()
		correct := VerifyPrepared(params, precomputed, signature, message)
		b.StopTimer()

		if !correct {
			b.Fatal("Signature is not valid")
		}
	}
}

func BenchmarkVerifyCached_5(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 5)
}

func BenchmarkVerifyCached_10(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 10)
}

func BenchmarkVerifyCached_15(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 15)
}

func BenchmarkVerifyCached_20(b *testing.B) {
	VerifyCachedBenchmarkHelper(b, 20)
}

func ResampleKeyBenchmarkHelper(b *testing.B, numAttributes int, delegable bool) {
	b.StopTimer()
	var err error

	// Set up parameters
	params, master := Setup(20, true)

	for i := 0; i < b.N; i++ {
		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, attrs)

		precomputed := PrepareAttributeList(params, attrs)

		b.StartTimer()
		_ = ResampleKey(params, precomputed, key, delegable)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkResampleKey_5(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 5, false)
}

func BenchmarkResampleKey_10(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 10, false)
}

func BenchmarkResampleKey_15(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 15, false)
}

func BenchmarkResampleKey_20(b *testing.B) {
	ResampleKeyBenchmarkHelper(b, 20, false)
}

func QualifyKeyEndBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()
	var err error

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master := Setup(20, true)

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, GroupOrder)
			if err != nil {
				b.Fatal(err)
			}
		}

		key := KeyGen(params, master, AttributeList{0: attrs[0]})

		b.StartTimer()
		_ = QualifyKey(params, key, attrs)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQualifyKeyEnd_5(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 5)
}

func BenchmarkQualifyKeyEnd_10(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 10)
}

func BenchmarkQualifyKeyEnd_15(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 15)
}

func BenchmarkQualifyKeyEnd_20(b *testing.B) {
	QualifyKeyEndBenchmarkHelper(b, 20)
}
