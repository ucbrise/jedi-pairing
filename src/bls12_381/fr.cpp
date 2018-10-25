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

#include "core/bigint.hpp"
#include "core/montgomeryfp.hpp"
#include "bls12_381/fr.hpp"

namespace embedded_pairing::bls12_381 {
    /* Constants for instantiating the MontgomeryFp class template for Fq. */
    extern constexpr BigInt<fr_bits> fr_modulus_var = fr_modulus;
    extern constexpr BigInt<fr_bits> fr_R_var = fr_R;
    extern constexpr BigInt<fr_bits> fr_R2_var = fr_R2;
    extern constexpr BigInt<fr_bits> fr_inv_var = fr_inv;

    static constexpr BigInt<fr_bits> fr_root_of_unity = {
        .std_words = {0x5f0e466a, 0xb9b58d8c, 0x1819d7ec, 0x5b1b4c80, 0x52a31e64, 0x0af53ae3, 0x19e9b27b, 0x5bf3adda}
    };
    // The constant t
    static constexpr BigInt<fr_bits> fr_t_constant = {
        .std_words = {0xffffffff, 0xfffe5bfe, 0x53bda402, 0x9a1d805, 0x3339d808, 0x299d7d48, 0x73eda753, 0x0}
    };
    // The constant (t + 1) // 2, used for computing the square root
    static constexpr BigInt<fr_bits> fr_tplusoneovertwo = {
        .std_words = {0x80000000, 0x7fff2dff, 0xa9ded201, 0x4d0ec02, 0x199cec04, 0x94cebea4, 0x39f6d3a9, 0x0}
    };

    // TODO: balance this function
    void Fr::square_root(const Fr& __restrict a) {
        if (a.is_zero()) {
            this->copy(a);
            return;
        }

        Fr c = {{{.val = fr_root_of_unity}}};
        Fr t;
        exponentiate(*this, a, fr_tplusoneovertwo);
        exponentiate(t, a, fr_t_constant);

        int m = 32;
        while (!t.is_one()) {
            int i = 1;
            Fr t2i;
            t2i.square(t);
            while (!t2i.is_one()) {
                t2i.square(t2i);
                i++;
            }

            for (int j = 0; j < m - i - 1; j++) {
                c.square(c);
            }
            this->multiply(*this, c);
            c.square(c);
            t.multiply(t, c);
            m = i;
        }
    }

    void Fr::random(void (*get_random_bytes)(void*, size_t)) {
        do {
            get_random_bytes(this->val.bytes, sizeof(this->val.bytes));
            // Discard the top bit, as the prime modulus is 0 in that bit
            this->val.bytes[BigInt<fr_bits>::byte_length - 1] &= 0x7F;
        } while (BigInt<fr_bits>::compare(this->val, fr_modulus) >= 0);
    }

    void Fr::hash_reduce() {
        // Discard the top bit, as the prime modulus is 0 in that bit
        this->val.bytes[BigInt<fr_bits>::byte_length - 1] &= 0x7F;
        if (BigInt<fr_bits>::compare(this->val, fr_modulus) == -1) {
#ifdef RESIST_SIDE_CHANNELS
            this->val.subtract(this->val, BigInt<bits>::zero);
#endif
        } else {
            this->val.subtract(this->val, fr_modulus);
        }
    }
}
