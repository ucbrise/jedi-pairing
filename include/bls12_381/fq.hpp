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

#ifndef EMBEDDED_PAIRING_BLS12_381_FQ_HPP_
#define EMBEDDED_PAIRING_BLS12_381_FQ_HPP_

#include <stdint.h>
#include "core/bigint.hpp"
#include "core/fp.hpp"
#include "core/fp_utils.hpp"

using embedded_pairing::core::BigInt;
using embedded_pairing::core::Fp;

namespace embedded_pairing::bls12_381 {
    static constexpr int fq_bits = 384;
    static constexpr BigInt<fq_bits> fq_modulus = {
        .std_words = { 0xffffaaab, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea }
    };
    static constexpr BigInt<fq_bits> fq_R = {
        .std_words = { 0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3 }
    };
    static constexpr BigInt<fq_bits> fq_R2 = {
        .std_words = { 0x1c341746, 0xf4df1f34, 0x9d104f1, 0xa76e6a6, 0x4c95b6d5, 0x8de5476c, 0x939d83c0, 0x67eb88a9, 0xb519952d, 0x9a793e85, 0x92cae3aa, 0x11988fe5 }
    };
    static constexpr BigInt<fq_bits> fq_inv = {
        .std_words = { 0xfffcfffd, 0x89f3fffc, 0xd9d113e8, 0x286adb92, 0xc8e30b48, 0x16ef2ef0, 0x8eb2db4c, 0x19ecca0e, 0xe268cf58, 0x68b316fe, 0xfeaafc94, 0xceb06106 }
    };

    extern const BigInt<fq_bits> fq_modulus_var;
    extern const BigInt<fq_bits> fq_R_var;
    extern const BigInt<fq_bits> fq_R2_var;
    extern const BigInt<fq_bits> fq_inv_var;

    struct Fq : Fp<fq_bits, fq_modulus_var, fq_R_var, fq_R2_var, fq_inv_var> {
        static const Fq zero;
        static const Fq one;
        static const Fq negative_one;

        static inline int compare(const Fq& a, const Fq& b) {
            return BigInt<fq_bits>::compare(a.val, b.val);
        }
        inline void inverse(const Fq& a) {
            fp_inverse(*this, a);
        }
        void square_root(const Fq& a);
        void random(void (*get_random_bytes)(void*, size_t));
        bool hash_reduce(void);
        void write_big_endian(uint8_t* buffer) const;
        void read_big_endian(const uint8_t* buffer);
    };

    constexpr Fq Fq::zero = {{{.val = {0}}}};
    constexpr Fq Fq::one = {{{.val = fq_R }}};
    constexpr Fq Fq::negative_one = {{{.val = {.std_words = {0xfffcaaae, 0x43f5ffff, 0xed47fffd, 0x32b7fff2, 0xa2e99d69, 0x7e83a49, 0x8332bb7a, 0xeca8f331, 0xa0f4c069, 0xef148d1e, 0x3eff0206, 0x40ab326}}}}};
}

#endif
