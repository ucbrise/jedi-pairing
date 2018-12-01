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

#ifndef EMBEDDED_PAIRING_BLS12_381_BLS12_381_H_
#define EMBEDDED_PAIRING_BLS12_381_BLS12_381_H_

#include <stdbool.h>
#include <stddef.h>
#include "core/core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    embedded_pairing_core_bigint_384_t val;
} embedded_pairing_bls12_381_fq_t;

typedef struct {
    embedded_pairing_bls12_381_fq_t c0;
    embedded_pairing_bls12_381_fq_t c1;
} embedded_pairing_bls12_381_fq2_t;

typedef struct {
    embedded_pairing_bls12_381_fq2_t c0;
    embedded_pairing_bls12_381_fq2_t c1;
    embedded_pairing_bls12_381_fq2_t c2;
} embedded_pairing_bls12_381_fq6_t;

typedef struct {
    embedded_pairing_bls12_381_fq6_t c0;
    embedded_pairing_bls12_381_fq6_t c1;
} embedded_pairing_bls12_381_fq12_t;

typedef struct {
    embedded_pairing_bls12_381_fq_t x;
    embedded_pairing_bls12_381_fq_t y;
    bool infinity;
} embedded_pairing_bls12_381_g1affine_t;

typedef struct {
    embedded_pairing_bls12_381_fq_t x;
    embedded_pairing_bls12_381_fq_t y;
    embedded_pairing_bls12_381_fq_t z;
} embedded_pairing_bls12_381_g1_t;

typedef struct {
    embedded_pairing_bls12_381_fq2_t x;
    embedded_pairing_bls12_381_fq2_t y;
    bool infinity;
} embedded_pairing_bls12_381_g2affine_t;

typedef struct {
    embedded_pairing_bls12_381_fq2_t x;
    embedded_pairing_bls12_381_fq2_t y;
    embedded_pairing_bls12_381_fq2_t z;
} embedded_pairing_bls12_381_g2_t;

typedef struct {
    embedded_pairing_bls12_381_g1affine_t* g1;
    embedded_pairing_bls12_381_g2affine_t* g2;
    embedded_pairing_bls12_381_g2_t _r;
} embedded_pairing_bls12_381_pair_t;

extern const embedded_pairing_bls12_381_g1_t* embedded_pairing_bls12_381_g1_zero;
extern const embedded_pairing_bls12_381_g1affine_t* embedded_pairing_bls12_381_g1affine_zero;
extern const embedded_pairing_bls12_381_g1affine_t* embedded_pairing_bls12_381_g1affine_generator;

extern const embedded_pairing_bls12_381_g2_t* embedded_pairing_bls12_381_g2_zero;
extern const embedded_pairing_bls12_381_g2affine_t* embedded_pairing_bls12_381_g2affine_zero;
extern const embedded_pairing_bls12_381_g2affine_t* embedded_pairing_bls12_381_g2affine_generator;

extern const embedded_pairing_bls12_381_fq12_t* embedded_pairing_bls12_381_gt_zero;
extern const embedded_pairing_bls12_381_fq12_t* embedded_pairing_bls12_381_gt_generator;

void embedded_pairing_bls12_381_zp_random(embedded_pairing_core_bigint_256_t* result, void (*get_random_bytes)(void*, size_t));
void embedded_pairing_bls12_381_zp_from_hash(embedded_pairing_core_bigint_256_t* result, const void* hash);

void embedded_pairing_bls12_381_g1_add(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1_t* b);
void embedded_pairing_bls12_381_g1_add_mixed(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1affine_t* b);
void embedded_pairing_bls12_381_g1_negate(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a);
void embedded_pairing_bls12_381_g1_double(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a);
void embedded_pairing_bls12_381_g1_multiply(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_core_bigint_256_t* scalar);
void embedded_pairing_bls12_381_g1_multiply_affine(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_core_bigint_256_t* scalar);
void embedded_pairing_bls12_381_g1_random(embedded_pairing_bls12_381_g1_t* result, void (*get_random_bytes)(void*, size_t));
bool embedded_pairing_bls12_381_g1_equal(const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1_t* b);

void embedded_pairing_bls12_381_g1_from_affine(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1affine_t* affine);
void embedded_pairing_bls12_381_g1affine_from_projective(embedded_pairing_bls12_381_g1affine_t* result, const embedded_pairing_bls12_381_g1_t* projective);
void embedded_pairing_bls12_381_g1affine_negate(embedded_pairing_bls12_381_g1affine_t* result, const embedded_pairing_bls12_381_g1affine_t* a);
void embedded_pairing_bls12_381_g1affine_from_hash(embedded_pairing_bls12_381_g1affine_t* result, const void* hash);
bool embedded_pairing_bls12_381_g1affine_equal(const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_bls12_381_g1affine_t* b);


void embedded_pairing_bls12_381_g2_add(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2_t* b);
void embedded_pairing_bls12_381_g2_add_mixed(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2affine_t* b);
void embedded_pairing_bls12_381_g2_negate(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a);
void embedded_pairing_bls12_381_g2_double(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a);
void embedded_pairing_bls12_381_g2_multiply(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_core_bigint_256_t* scalar);
void embedded_pairing_bls12_381_g2_multiply_affine(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2affine_t* a, const embedded_pairing_core_bigint_256_t* scalar);
void embedded_pairing_bls12_381_g2_random(embedded_pairing_bls12_381_g2_t* result, void (*get_random_bytes)(void*, size_t));
bool embedded_pairing_bls12_381_g2_equal(const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2_t* b);

void embedded_pairing_bls12_381_g2_from_affine(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2affine_t* affine);
void embedded_pairing_bls12_381_g2affine_from_projective(embedded_pairing_bls12_381_g2affine_t* result, const embedded_pairing_bls12_381_g2_t* projective);
void embedded_pairing_bls12_381_g2affine_negate(embedded_pairing_bls12_381_g2affine_t* result, const embedded_pairing_bls12_381_g2affine_t* a);
void embedded_pairing_bls12_381_g2affine_from_hash(embedded_pairing_bls12_381_g2affine_t* result, const void* hash);
bool embedded_pairing_bls12_381_g2affine_equal(const embedded_pairing_bls12_381_g2affine_t* a, const embedded_pairing_bls12_381_g2affine_t* b);

void embedded_pairing_bls12_381_gt_add(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_bls12_381_fq12_t* b);
void embedded_pairing_bls12_381_gt_negate(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a);
void embedded_pairing_bls12_381_gt_double(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a);
void embedded_pairing_bls12_381_gt_multiply(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_core_bigint_256_t* scalar);
void embedded_pairing_bls12_381_gt_multiply_random(embedded_pairing_bls12_381_fq12_t* result, embedded_pairing_core_bigint_256_t* scalar, const embedded_pairing_bls12_381_fq12_t* base, void (*get_random_bytes)(void*, size_t));
bool embedded_pairing_bls12_381_gt_equal(const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_bls12_381_fq12_t* b);

void embedded_pairing_bls12_381_pairing(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_bls12_381_g2affine_t* b);
void embedded_pairing_bls12_381_pairing_sum(embedded_pairing_bls12_381_fq12_t* result, embedded_pairing_bls12_381_pair_t* pairs, size_t num_pairs);

#ifdef __cplusplus
}
#endif

#endif
