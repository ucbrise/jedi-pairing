/*
 * Copyright (c) 2020, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2020, University of California, Berkeley
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
#include "bls12_381/pairing.hpp"
#include "bls12_381/decomposition.hpp"

namespace embedded_pairing::bls12_381 {
    static constexpr BigInt<128> bls_x_squared = {.std_words = {0x00000000, 0x00000001, 0x0001a402, 0xac45a401}};
    static constexpr BigInt<192> bls_x_cubed = {.std_words = {0x00000000, 0x00010000, 0x76030000, 0xec030002, 0x760304d0, 0x8d51ccce}};

    /*
     * Decomposes a chosen value y into c0, c1, c2, c3 such that each c is in
     * [0, |x|) and y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3. The argument y must
     * be in the interval [0, r).
     */
    static void div_exp_coeff(BigInt<64>& __restrict c0, BigInt<64>& __restrict c1, BigInt<64>& __restrict c2, BigInt<64>& __restrict c3, const BigInt<256>& __restrict y) {
        BigInt<256> quotient;

        constexpr uint64_t x = (((uint64_t) bls_x.std_words[1]) << 32) | (uint64_t) (bls_x.std_words[0]);
        c0.std_dwords[0] = quotient.divide_std_dword<x>(y);
        c1.std_dwords[0] = quotient.divide_std_dword<x>(quotient);
        c2.std_dwords[0] = quotient.divide_std_dword<x>(quotient);
        c3.std_dwords[0] = quotient.std_dwords[0];
    }

    void PowersOfX::decompose(const BigInt<256>& __restrict y) {
        if (BigInt<256>::compare(y, Fr::p_value) == -1) {
            div_exp_coeff(this->c[0], this->c[1], this->c[2], this->c[3], y);
        } else {
            BigInt<256> a;
            a.subtract(y, Fr::p_value);
            div_exp_coeff(this->c[0], this->c[1], this->c[2], this->c[3], a);
        }
    }

    void PowersOfX::random(BigInt<256>& __restrict y, void (*get_random_bytes)(void*, size_t)) {
        do {
            for (unsigned int i = 0; i != 4; i++) {
                do {
                    this->c[i].random(get_random_bytes);
                } while (BigInt<64>::compare(this->c[i], bls_x) != -1);
            }

            BigInt<128> t1;
            BigInt<128> t2;
            t1.multiply(this->c[1], bls_x);
            t2.copy(this->c[0]);
            t1.add(t1, t2);

            BigInt<192> t3;
            BigInt<192> t4;
            t3.multiply(this->c[2], bls_x_squared);
            t4.copy(t1);
            t3.add(t3, t4);

            BigInt<256> t6;
            y.multiply(this->c[3], bls_x_cubed);
            t6.copy(t3);
            y.add(y, t6);
        } while (BigInt<256>::compare(y, Fr::p_value) != -1);
    }
}
