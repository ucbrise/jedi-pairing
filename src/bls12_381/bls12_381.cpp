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

#include "bls12_381/bls12_381.h"

#include <stdint.h>

#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"
#include "bls12_381/wnaf.hpp"

using namespace embedded_pairing::bls12_381;
using embedded_pairing::core::BigInt;

extern "C" {
    const embedded_pairing_core_bigint_256_t* embedded_pairing_bls12_381_group_order = (const embedded_pairing_core_bigint_256_t*) &fr_modulus;

    const embedded_pairing_bls12_381_g1_t* embedded_pairing_bls12_381_g1_zero = (const embedded_pairing_bls12_381_g1_t*) &G1::zero;
    const embedded_pairing_bls12_381_g1affine_t* embedded_pairing_bls12_381_g1affine_zero = (const embedded_pairing_bls12_381_g1affine_t*) &G1Affine::zero;
    const embedded_pairing_bls12_381_g1affine_t* embedded_pairing_bls12_381_g1affine_generator = (const embedded_pairing_bls12_381_g1affine_t*) &G1Affine::generator;

    const embedded_pairing_bls12_381_g2_t* embedded_pairing_bls12_381_g2_zero = (const embedded_pairing_bls12_381_g2_t*) &G2::zero;
    const embedded_pairing_bls12_381_g2affine_t* embedded_pairing_bls12_381_g2affine_zero = (const embedded_pairing_bls12_381_g2affine_t*) &G2Affine::zero;
    const embedded_pairing_bls12_381_g2affine_t* embedded_pairing_bls12_381_g2affine_generator = (const embedded_pairing_bls12_381_g2affine_t*) &G2Affine::generator;

    const embedded_pairing_bls12_381_fq12_t* embedded_pairing_bls12_381_gt_zero = (const embedded_pairing_bls12_381_fq12_t*) &Fq12::one;
    const embedded_pairing_bls12_381_fq12_t* embedded_pairing_bls12_381_gt_generator = (const embedded_pairing_bls12_381_fq12_t*) &generator_pairing;

    const size_t embedded_pairing_bls12_381_g1_marshalled_compressed_size = Encoding<G1Affine, true>::size;
    const size_t embedded_pairing_bls12_381_g1_marshalled_uncompressed_size = Encoding<G1Affine, false>::size;

    const size_t embedded_pairing_bls12_381_g2_marshalled_compressed_size = Encoding<G2Affine, true>::size;
    const size_t embedded_pairing_bls12_381_g2_marshalled_uncompressed_size = Encoding<G2Affine, false>::size;

    const size_t embedded_pairing_bls12_381_gt_marshalled_size = sizeof(Fq12);
}

void embedded_pairing_bls12_381_zp_random(embedded_pairing_core_bigint_256_t* result, void (*get_random_bytes)(void*, size_t)) {
    reinterpret_cast<Fr*>(result)->random(get_random_bytes);
}

void embedded_pairing_bls12_381_zp_from_hash(embedded_pairing_core_bigint_256_t* result, const void* hash) {
    Fr* res = reinterpret_cast<Fr*>(result);
    res->val.read_big_endian(static_cast<const uint8_t*>(hash));
    res->hash_reduce();
}

void embedded_pairing_bls12_381_g1_add(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1_t* b) {
    reinterpret_cast<G1*>(result)->add(*reinterpret_cast<const G1*>(a), *reinterpret_cast<const G1*>(b));
}

void embedded_pairing_bls12_381_g1_add_mixed(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1affine_t* b) {
    reinterpret_cast<G1*>(result)->add(*reinterpret_cast<const G1*>(a), *reinterpret_cast<const G1Affine*>(b));
}

void embedded_pairing_bls12_381_g1_negate(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a) {
    reinterpret_cast<G1*>(result)->negate(*reinterpret_cast<const G1*>(a));
}

void embedded_pairing_bls12_381_g1_double(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a) {
    reinterpret_cast<G1*>(result)->multiply2(*reinterpret_cast<const G1*>(a));
}

void embedded_pairing_bls12_381_g1_multiply(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_core_bigint_256_t* scalar) {
    wnaf_multiply(*reinterpret_cast<G1*>(result), *reinterpret_cast<const G1*>(a), *reinterpret_cast<const BigInt<256>*>(scalar));
}

void embedded_pairing_bls12_381_g1_multiply_affine(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_core_bigint_256_t* scalar) {
    wnaf_multiply(*reinterpret_cast<G1*>(result), *reinterpret_cast<const G1Affine*>(a), *reinterpret_cast<const BigInt<256>*>(scalar));
}

void embedded_pairing_bls12_381_g1_random(embedded_pairing_bls12_381_g1_t* result, void (*get_random_bytes)(void*, size_t)) {
    reinterpret_cast<G1*>(result)->random_generator(get_random_bytes);
}

bool embedded_pairing_bls12_381_g1_equal(const embedded_pairing_bls12_381_g1_t* a, const embedded_pairing_bls12_381_g1_t* b) {
    return G1::equal(*reinterpret_cast<const G1*>(a), *reinterpret_cast<const G1*>(b));
}

void embedded_pairing_bls12_381_g1_from_affine(embedded_pairing_bls12_381_g1_t* result, const embedded_pairing_bls12_381_g1affine_t* affine) {
    reinterpret_cast<G1*>(result)->from_affine(*reinterpret_cast<const G1Affine*>(affine));
}

void embedded_pairing_bls12_381_g1affine_from_projective(embedded_pairing_bls12_381_g1affine_t* result, const embedded_pairing_bls12_381_g1_t* projective) {
    reinterpret_cast<G1Affine*>(result)->from_projective(*reinterpret_cast<const G1*>(projective));
}

void embedded_pairing_bls12_381_g1affine_negate(embedded_pairing_bls12_381_g1affine_t* result, const embedded_pairing_bls12_381_g1affine_t* a) {
    reinterpret_cast<G1Affine*>(result)->negate(*reinterpret_cast<const G1Affine*>(a));
}

void embedded_pairing_bls12_381_g1affine_from_hash(embedded_pairing_bls12_381_g1affine_t* result, const void* hash) {
    reinterpret_cast<G1Affine*>(result)->from_hash(static_cast<const uint8_t*>(hash));
}

bool embedded_pairing_bls12_381_g1affine_equal(const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_bls12_381_g1affine_t* b) {
    return G1Affine::equal(*reinterpret_cast<const G1Affine*>(a), *reinterpret_cast<const G1Affine*>(b));
}

void embedded_pairing_bls12_381_g2_add(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2_t* b) {
    reinterpret_cast<G2*>(result)->add(*reinterpret_cast<const G2*>(a), *reinterpret_cast<const G2*>(b));
}

void embedded_pairing_bls12_381_g2_add_mixed(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2affine_t* b) {
    reinterpret_cast<G2*>(result)->add(*reinterpret_cast<const G2*>(a), *reinterpret_cast<const G2Affine*>(b));
}

void embedded_pairing_bls12_381_g2_negate(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a) {
    reinterpret_cast<G2*>(result)->negate(*reinterpret_cast<const G2*>(a));
}

void embedded_pairing_bls12_381_g2_double(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a) {
    reinterpret_cast<G2*>(result)->multiply2(*reinterpret_cast<const G2*>(a));
}

void embedded_pairing_bls12_381_g2_multiply(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_core_bigint_256_t* scalar) {
    wnaf_multiply(*reinterpret_cast<G2*>(result), *reinterpret_cast<const G2*>(a), *reinterpret_cast<const BigInt<256>*>(scalar));
}

void embedded_pairing_bls12_381_g2_multiply_affine(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2affine_t* a, const embedded_pairing_core_bigint_256_t* scalar) {
    wnaf_multiply(*reinterpret_cast<G2*>(result), *reinterpret_cast<const G2Affine*>(a), *reinterpret_cast<const BigInt<256>*>(scalar));
}

void embedded_pairing_bls12_381_g2_random(embedded_pairing_bls12_381_g2_t* result, void (*get_random_bytes)(void*, size_t)) {
    reinterpret_cast<G2*>(result)->random_generator(get_random_bytes);
}

bool embedded_pairing_bls12_381_g2_equal(const embedded_pairing_bls12_381_g2_t* a, const embedded_pairing_bls12_381_g2_t* b) {
    return G2::equal(*reinterpret_cast<const G2*>(a), *reinterpret_cast<const G2*>(b));
}

void embedded_pairing_bls12_381_g2_from_affine(embedded_pairing_bls12_381_g2_t* result, const embedded_pairing_bls12_381_g2affine_t* affine) {
    reinterpret_cast<G2*>(result)->from_affine(*reinterpret_cast<const G2Affine*>(affine));
}

void embedded_pairing_bls12_381_g2affine_from_projective(embedded_pairing_bls12_381_g2affine_t* result, const embedded_pairing_bls12_381_g2_t* projective) {
    reinterpret_cast<G2Affine*>(result)->from_projective(*reinterpret_cast<const G2*>(projective));
}

void embedded_pairing_bls12_381_g2affine_negate(embedded_pairing_bls12_381_g2affine_t* result, const embedded_pairing_bls12_381_g2affine_t* a) {
    reinterpret_cast<G2Affine*>(result)->negate(*reinterpret_cast<const G2Affine*>(a));
}

void embedded_pairing_bls12_381_g2affine_from_hash(embedded_pairing_bls12_381_g2affine_t* result, const void* hash) {
    reinterpret_cast<G2Affine*>(result)->from_hash(static_cast<const uint8_t*>(hash));
}

bool embedded_pairing_bls12_381_g2affine_equal(const embedded_pairing_bls12_381_g2affine_t* a, const embedded_pairing_bls12_381_g2affine_t* b) {
    return G2Affine::equal(*reinterpret_cast<const G2Affine*>(a), *reinterpret_cast<const G2Affine*>(b));
}

void embedded_pairing_bls12_381_g2prepared_prepare(embedded_pairing_bls12_381_g2prepared_t* result, const embedded_pairing_bls12_381_g2affine_t* a) {
    reinterpret_cast<G2Prepared*>(result)->prepare(*reinterpret_cast<const G2Affine*>(a));
}

bool embedded_pairing_bls12_381_g2prepared_is_zero(const embedded_pairing_bls12_381_g2prepared_t* a) {
    return reinterpret_cast<const G2Prepared*>(a)->is_zero();
}

void embedded_pairing_bls12_381_gt_add(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_bls12_381_fq12_t* b) {
    reinterpret_cast<Fq12*>(result)->multiply(*reinterpret_cast<const Fq12*>(a), *reinterpret_cast<const Fq12*>(b));
}

void embedded_pairing_bls12_381_gt_negate(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a) {
    reinterpret_cast<Fq12*>(result)->inverse(*reinterpret_cast<const Fq12*>(a));
}

void embedded_pairing_bls12_381_gt_double(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a) {
    reinterpret_cast<Fq12*>(result)->square_cyclotomic(*reinterpret_cast<const Fq12*>(a));
}

void embedded_pairing_bls12_381_gt_multiply(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_core_bigint_256_t* scalar) {
    reinterpret_cast<Fq12*>(result)->exponentiate_cyclotomic(*reinterpret_cast<const Fq12*>(a), *reinterpret_cast<const BigInt<256>*>(scalar));
}

void embedded_pairing_bls12_381_gt_multiply_random(embedded_pairing_bls12_381_fq12_t* result, embedded_pairing_core_bigint_256_t* scalar, const embedded_pairing_bls12_381_fq12_t* base, void (*get_random_bytes)(void*, size_t)) {
    BigInt<256>* s = reinterpret_cast<BigInt<256>*>(scalar);
    reinterpret_cast<Fq12*>(result)->random_gt(*s, *reinterpret_cast<const Fq12*>(base), get_random_bytes);
}

bool embedded_pairing_bls12_381_gt_equal(const embedded_pairing_bls12_381_fq12_t* a, const embedded_pairing_bls12_381_fq12_t* b) {
    return Fq12::equal(*reinterpret_cast<const Fq12*>(a), *reinterpret_cast<const Fq12*>(b));
}

void embedded_pairing_bls12_381_pairing(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_bls12_381_g2affine_t* b) {
    pairing(*reinterpret_cast<Fq12*>(result), *reinterpret_cast<const G1Affine*>(a), *reinterpret_cast<const G2Affine*>(b));
}

void embedded_pairing_bls12_381_prepared_pairing(embedded_pairing_bls12_381_fq12_t* result, const embedded_pairing_bls12_381_g1affine_t* a, const embedded_pairing_bls12_381_g2prepared_t* b) {
    pairing(*reinterpret_cast<Fq12*>(result), *reinterpret_cast<const G1Affine*>(a), *reinterpret_cast<const G2Prepared*>(b));
}

void embedded_pairing_bls12_381_pairing_sum(embedded_pairing_bls12_381_fq12_t* result, embedded_pairing_bls12_381_affine_pair_t* affine_pairs, size_t num_affine_pairs, embedded_pairing_bls12_381_prepared_pair_t* prepared_pairs, size_t num_prepared_pairs) {
    pairing_product(*reinterpret_cast<Fq12*>(result), reinterpret_cast<AffinePair*>(affine_pairs), num_affine_pairs, reinterpret_cast<PreparedPair*>(prepared_pairs), num_prepared_pairs);
}

void embedded_pairing_bls12_381_g1_marshal(void* buffer, const embedded_pairing_bls12_381_g1affine_t* a, bool compressed) {
    if (compressed) {
        Encoding<G1Affine, true>* encoding = static_cast<Encoding<G1Affine, true>*>(buffer);
        encoding->encode(*reinterpret_cast<const G1Affine*>(a));
    } else {
        Encoding<G1Affine, false>* encoding = static_cast<Encoding<G1Affine, false>*>(buffer);
        encoding->encode(*reinterpret_cast<const G1Affine*>(a));
    }
}

bool embedded_pairing_bls12_381_g1_unmarshal(embedded_pairing_bls12_381_g1affine_t* a, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        const Encoding<G1Affine, true>* encoding = static_cast<const Encoding<G1Affine, true>*>(buffer);
        return encoding->decode(*reinterpret_cast<G1Affine*>(a), checked);
    } else {
        const Encoding<G1Affine, false>* encoding = static_cast<const Encoding<G1Affine, false>*>(buffer);
        return encoding->decode(*reinterpret_cast<G1Affine*>(a), checked);
    }
}

void embedded_pairing_bls12_381_g2_marshal(void* buffer, const embedded_pairing_bls12_381_g2affine_t* a, bool compressed) {
    if (compressed) {
        Encoding<G2Affine, true>* encoding = static_cast<Encoding<G2Affine, true>*>(buffer);
        encoding->encode(*reinterpret_cast<const G2Affine*>(a));
    } else {
        Encoding<G2Affine, false>* encoding = static_cast<Encoding<G2Affine, false>*>(buffer);
        encoding->encode(*reinterpret_cast<const G2Affine*>(a));
    }
}

bool embedded_pairing_bls12_381_g2_unmarshal(embedded_pairing_bls12_381_g2affine_t* a, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        const Encoding<G2Affine, true>* encoding = static_cast<const Encoding<G2Affine, true>*>(buffer);
        return encoding->decode(*reinterpret_cast<G2Affine*>(a), checked);
    } else {
        const Encoding<G2Affine, false>* encoding = static_cast<const Encoding<G2Affine, false>*>(buffer);
        return encoding->decode(*reinterpret_cast<G2Affine*>(a), checked);
    }
}

void embedded_pairing_bls12_381_gt_marshal(void* buffer, const embedded_pairing_bls12_381_fq12_t* a) {
    reinterpret_cast<const Fq12*>(a)->write_big_endian(static_cast<uint8_t*>(buffer));
}

void embedded_pairing_bls12_381_gt_unmarshal(embedded_pairing_bls12_381_fq12_t* a, const void* buffer) {
    reinterpret_cast<Fq12*>(a)->read_big_endian(static_cast<const uint8_t*>(buffer));
}
