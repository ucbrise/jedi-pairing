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

#ifndef EMBEDDED_PAIRING_WKDIBE_WKDIBE_H_
#define EMBEDDED_PAIRING_WKDIBE_WKDIBE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/core.h"
#include "bls12_381/bls12_381.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef embedded_pairing_core_bigint_256_t embedded_pairing_wkdibe_scalar_t;
typedef embedded_pairing_bls12_381_g1affine_t embedded_pairing_wkdibe_g1affine_t;
typedef embedded_pairing_bls12_381_g1_t embedded_pairing_wkdibe_g1_t;
typedef embedded_pairing_bls12_381_g2affine_t embedded_pairing_wkdibe_g2affine_t;
typedef embedded_pairing_bls12_381_g2_t embedded_pairing_wkdibe_g2_t;
typedef embedded_pairing_bls12_381_fq12_t embedded_pairing_wkdibe_gt_t;

typedef struct {
    embedded_pairing_wkdibe_scalar_t id;
    uint32_t idx;
    bool omitFromKeys;
} embedded_pairing_wkdibe_attribute_t;

typedef struct {
    embedded_pairing_wkdibe_attribute_t* attrs;
    size_t length;
    bool omitAllFromKeysUnlessPresent;
} embedded_pairing_wkdibe_attributelist_t;

typedef struct {
    embedded_pairing_wkdibe_g2_t g;
    embedded_pairing_wkdibe_g2_t g1;
    embedded_pairing_wkdibe_g1_t g2;
    embedded_pairing_wkdibe_g1_t g3;
    embedded_pairing_wkdibe_gt_t pairing;

    embedded_pairing_wkdibe_g1_t hsig;
    bool signatures;

    embedded_pairing_wkdibe_g1_t* h;
    int l;
} embedded_pairing_wkdibe_params_t;

typedef struct {
    embedded_pairing_wkdibe_gt_t a;
    embedded_pairing_wkdibe_g2_t b;
    embedded_pairing_wkdibe_g1_t c;
} embedded_pairing_wkdibe_ciphertext_t;

typedef struct {
    embedded_pairing_wkdibe_g1_t a0;
    embedded_pairing_wkdibe_g2_t a1;
} embedded_pairing_wkdibe_signature_t;

typedef struct {
    embedded_pairing_wkdibe_g1_t hexp;
    uint32_t idx;
} embedded_pairing_wkdibe_freeslot_t;

typedef struct {
    embedded_pairing_wkdibe_g1_t a0;
    embedded_pairing_wkdibe_g2_t a1;

    int l;
    bool signatures;
    embedded_pairing_wkdibe_g1_t bsig;
    embedded_pairing_wkdibe_freeslot_t* b;
} embedded_pairing_wkdibe_secretkey_t;

typedef struct {
    embedded_pairing_wkdibe_g1_t g2alpha;
} embedded_pairing_wkdibe_masterkey_t;

typedef struct {
    embedded_pairing_wkdibe_g1_t prodexp;
} embedded_pairing_wkdibe_precomputed_t;

void embedded_pairing_wkdibe_scalar_hash_reduce(embedded_pairing_wkdibe_scalar_t* x);

void embedded_pairing_wkdibe_random_zpstar(embedded_pairing_wkdibe_scalar_t* x, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_random_g1(embedded_pairing_wkdibe_g1_t* g1, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_random_g2(embedded_pairing_wkdibe_g2_t* g2, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_random_gt(embedded_pairing_wkdibe_gt_t* gt, void (*get_random_bytes)(void*, size_t));

void embedded_pairing_wkdibe_setup(embedded_pairing_wkdibe_params_t* params, embedded_pairing_wkdibe_masterkey_t* msk, int l, bool signatures, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_keygen(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_masterkey_t* msk, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_qualifykey(embedded_pairing_wkdibe_secretkey_t* qualified, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_nondelegable_keygen(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_masterkey_t* msk, const embedded_pairing_wkdibe_attributelist_t* attrs);
void embedded_pairing_wkdibe_nondelegable_qualifykey(embedded_pairing_wkdibe_secretkey_t* qualified, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs);
void embedded_pairing_wkdibe_adjust_nondelegable(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_secretkey_t* parent, const embedded_pairing_wkdibe_attributelist_t* from, const embedded_pairing_wkdibe_attributelist_t* to);

void embedded_pairing_wkdibe_precompute(embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs);
void embedded_pairing_wkdibe_adjust_precomputed(embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* from, const embedded_pairing_wkdibe_attributelist_t* to);
void embedded_pairing_wkdibe_resamplekey(embedded_pairing_wkdibe_secretkey_t* resampled, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_secretkey_t* sk, bool supportFurtherQualification, void (*get_random_bytes)(void*, size_t));

void embedded_pairing_wkdibe_encrypt(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_encrypt_precomputed(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_decrypt(embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_secretkey_t* sk);
void embedded_pairing_wkdibe_decrypt_master(embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_masterkey_t* msk);

void embedded_pairing_wkdibe_sign(embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_scalar_t* message, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_wkdibe_sign_precomputed(embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_scalar_t* message, void (*get_random_bytes)(void*, size_t));
bool embedded_pairing_wkdibe_verify(const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_scalar_t* message);
bool embedded_pairing_wkdibe_verify_precomputed(const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_scalar_t* message);

void embedded_pairing_wkdibe_params_marshal(void* buffer, const embedded_pairing_wkdibe_params_t* params, bool compressed);
bool embedded_pairing_wkdibe_params_unmarshal(embedded_pairing_wkdibe_params_t* params, const void* buffer, bool compressed, bool checked);
int embedded_pairing_wkdibe_params_set_length(embedded_pairing_wkdibe_params_t* params, const void* marshalled, size_t marshalled_length, bool compressed);
size_t embedded_pairing_wkdibe_params_get_marshalled_length(const embedded_pairing_wkdibe_params_t* params, bool compressed);
int embedded_pairing_wkdibe_params_unmarshalled_length(const void* marshalled, size_t marshalled_length, bool compressed);
size_t embedded_pairing_wkdibe_params_marshalled_length(int length, bool signatures, bool compressed);

void embedded_pairing_wkdibe_ciphertext_marshal(void* buffer, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, bool compressed);
bool embedded_pairing_wkdibe_ciphertext_unmarshal(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_wkdibe_ciphertext_get_marshalled_length(bool compressed);

void embedded_pairing_wkdibe_signature_marshal(void* buffer, const embedded_pairing_wkdibe_signature_t* signature, bool compressed);
bool embedded_pairing_wkdibe_signature_unmarshal(embedded_pairing_wkdibe_signature_t* signature, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_wkdibe_signature_get_marshalled_length(bool compressed);

void embedded_pairing_wkdibe_secretkey_marshal(void* buffer, const embedded_pairing_wkdibe_secretkey_t* secretkey, bool compressed);
bool embedded_pairing_wkdibe_secretkey_unmarshal(embedded_pairing_wkdibe_secretkey_t* secretkey, const void* buffer, bool compressed, bool checked);
int embedded_pairing_wkdibe_secretkey_set_length(embedded_pairing_wkdibe_secretkey_t* secretkey, const void* marshalled, size_t marshalled_length, bool compressed);
size_t embedded_pairing_wkdibe_secretkey_get_marshalled_length(const embedded_pairing_wkdibe_secretkey_t* secretkey, bool compressed);
int embedded_pairing_wkdibe_secretkey_unmarshalled_length(const void* marshalled, size_t marshalled_length, bool compressed);
size_t embedded_pairing_wkdibe_secretkey_marshalled_length(int length, bool signatures, bool compressed);

void embedded_pairing_wkdibe_masterkey_marshal(void* buffer, const embedded_pairing_wkdibe_masterkey_t* masterkey, bool compressed);
bool embedded_pairing_wkdibe_masterkey_unmarshal(embedded_pairing_wkdibe_masterkey_t* masterkey, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_wkdibe_masterkey_get_marshalled_length(bool compressed);

#ifdef __cplusplus
}
#endif

#endif
