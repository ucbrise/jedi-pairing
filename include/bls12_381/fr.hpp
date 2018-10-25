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

#ifndef EMBEDDED_PAIRING_BLS12_381_FR_HPP_
#define EMBEDDED_PAIRING_BLS12_381_FR_HPP_

#include <stddef.h>

#include "core/bigint.hpp"
#include "core/montgomeryfp.hpp"

using embedded_pairing::core::BigInt;
using embedded_pairing::core::MontgomeryFp;

namespace embedded_pairing::bls12_381 {
    static constexpr int fr_bits = 256;
    static constexpr BigInt<fr_bits> fr_modulus = {.std_words = { 0x00000001, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x09a1d805, 0x3339d808, 0x299d7d48, 0x73eda753 }};
    static constexpr BigInt<fr_bits> fr_R = {.std_words = { 0xfffffffe, 0x00000001, 0x00034802, 0x5884b7fa, 0xecbc4ff5, 0x998c4fef, 0xacc5056f, 0x1824b159 }};
    static constexpr BigInt<fr_bits> fr_R2 = {.std_words = { 0xf3f29c6d, 0xc999e990, 0x87925c23, 0x2b6cedcb, 0x7254398f, 0x05d31496, 0x9f59ff11, 0x0748d9d9 }};
    static constexpr BigInt<fr_bits> fr_inv = {.std_words = { 0xffffffff, 0xfffffffe, 0xfffe5bfd, 0x53ba5bff, 0x0004ec06, 0x181b2c17, 0xd7bf2839, 0x3d443ab0 }};

    extern const BigInt<fr_bits> fr_modulus_var;
    extern const BigInt<fr_bits> fr_R_var;
    extern const BigInt<fr_bits> fr_R2_var;
    extern const BigInt<fr_bits> fr_inv_var;

    struct Fr : MontgomeryFp<fr_bits, fr_modulus_var, fr_R_var, fr_R2_var, fr_inv_var> {
        static const Fr zero;
        static const Fr one;

        void square_root(const Fr& __restrict a);
        void random(void (*get_random_bytes)(void*, size_t));
        void hash_reduce(void);
    };

    constexpr Fr Fr::zero = {{{ .val = {0} }}};
    constexpr Fr Fr::one = {{{ .val = fr_R }}};
}

#endif
