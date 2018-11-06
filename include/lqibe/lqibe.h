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

#ifndef EMBEDDED_PAIRING_LQIBE_LQIBE_H_
#define EMBEDDED_PAIRING_LQIBE_LQIBE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/core.h"
#include "bls12_381/bls12_381.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef embedded_pairing_core_bigint_256_t embedded_pairing_lqibe_scalar_t;
typedef embedded_pairing_bls12_381_g1affine_t embedded_pairing_lqibe_g1affine_t;
typedef embedded_pairing_bls12_381_g1_t embedded_pairing_lqibe_g1_t;
typedef embedded_pairing_bls12_381_g2affine_t embedded_pairing_lqibe_g2affine_t;
typedef embedded_pairing_bls12_381_g2_t embedded_pairing_lqibe_g2_t;
typedef embedded_pairing_bls12_381_fq12_t embedded_pairing_lqibe_gt_t;

typedef struct {
    uint8_t hash[sizeof(embedded_pairing_bls12_381_fq2_t)];
} embedded_pairing_lqibe_idhash_t;

typedef struct {
    embedded_pairing_lqibe_g1_t p;
    embedded_pairing_lqibe_g1_t sp;
} embedded_pairing_lqibe_params_t;

typedef struct {
    embedded_pairing_lqibe_g2_t q;
} embedded_pairing_lqibe_id_t;

typedef struct {
    embedded_pairing_lqibe_scalar_t s;
} embedded_pairing_lqibe_masterkey_t;

typedef struct {
    embedded_pairing_lqibe_g2affine_t sq;
} embedded_pairing_lqibe_secretkey_t;

typedef struct {
    embedded_pairing_lqibe_g1_t rp;
} embedded_pairing_lqibe_ciphertext_t;

void embedded_pairing_lqibe_compute_id_from_hash(embedded_pairing_lqibe_id_t* id, const embedded_pairing_lqibe_idhash_t* hash);

void embedded_pairing_lqibe_setup(embedded_pairing_lqibe_params_t* params, embedded_pairing_lqibe_masterkey_t* msk, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_lqibe_keygen(embedded_pairing_lqibe_secretkey_t* sk, const embedded_pairing_lqibe_masterkey_t* msk, const embedded_pairing_lqibe_id_t* id);
void embedded_pairing_lqibe_encrypt(embedded_pairing_lqibe_ciphertext_t* ciphertext, void* symmetric, size_t symmetric_length, const embedded_pairing_lqibe_params_t* params, const embedded_pairing_lqibe_id_t* id, void (*hash_fill)(void*, size_t, const void*, size_t), void (*get_random_bytes)(void*, size_t));
void embedded_pairing_lqibe_decrypt(void* symmetric, size_t symmetric_length, const embedded_pairing_lqibe_ciphertext_t* ciphertext, const embedded_pairing_lqibe_secretkey_t* sk, const embedded_pairing_lqibe_id_t* id, void (*hash_fill)(void*, size_t, const void*, size_t));

void embedded_pairing_lqibe_params_marshal(void* buffer, const embedded_pairing_lqibe_params_t* params, bool compressed);
bool embedded_pairing_lqibe_params_unmarshal(embedded_pairing_lqibe_params_t* params, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_lqibe_params_get_marshalled_length(bool compressed);

void embedded_pairing_lqibe_id_marshal(void* buffer, const embedded_pairing_lqibe_id_t* id, bool compressed);
bool embedded_pairing_lqibe_id_unmarshal(embedded_pairing_lqibe_id_t* id, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_lqibe_id_get_marshalled_length(bool compressed);

void embedded_pairing_lqibe_masterkey_marshal(void* buffer, const embedded_pairing_lqibe_masterkey_t* masterkey, bool compressed);
bool embedded_pairing_lqibe_masterkey_unmarshal(embedded_pairing_lqibe_masterkey_t* masterkey, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_lqibe_masterkey_get_marshalled_length(bool compressed);

void embedded_pairing_lqibe_secretkey_marshal(void* buffer, const embedded_pairing_lqibe_secretkey_t* secretkey, bool compressed);
bool embedded_pairing_lqibe_secretkey_unmarshal(embedded_pairing_lqibe_secretkey_t* secretkey, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_lqibe_secretkey_get_marshalled_length(bool compressed);

void embedded_pairing_lqibe_ciphertext_marshal(void* buffer, const embedded_pairing_lqibe_ciphertext_t* ciphertext, bool compressed);
bool embedded_pairing_lqibe_ciphertext_unmarshal(embedded_pairing_lqibe_ciphertext_t* ciphertext, const void* buffer, bool compressed, bool checked);
size_t embedded_pairing_lqibe_ciphertext_get_marshalled_length(bool compressed);

#ifdef __cplusplus
}
#endif

#endif
