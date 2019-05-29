/*
 * Copyright (c) 2019, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2019, University of California, Berkeley
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

/*
 * Although I wrote this code, it is based on techniques used by RELIC (see
 * https://github.com/relic-toolkit/relic), specifically in the files
 * src/ep/relic_ep_mul.c and src/epx/relic_ep2_mul.c. I am using
 * RELIC under the Apache 2.0 License (which RELIC provides as a licensing
 * option, at the time of writing), so the corresponding functions below are
 * also subject to the Apache 2.0 License.
 */

#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"
#include "bls12_381/wnaf.hpp"

namespace embedded_pairing::bls12_381 {
    static constexpr Fq2 uplusonetotheqminusoneoversix = {
        {{{{.std_words = {0xb319d465, 0x7089552, 0xb50a8313, 0xc6695f92, 0xd117228f, 0x97e83ccc, 0xb2dc29ee, 0xa35baeca, 0x5daace4d, 0x1ce393ea, 0xb0fb66eb, 0x8f2220f}}}}},
        {{{{.std_words = {0x4ce5d646, 0xb2f66aad, 0xfc497cec, 0x5842a06b, 0x2599d394, 0xcf4895d4, 0x40a8e8d0, 0xc11b9cba, 0xe5a0de89, 0x2e3813cb, 0x88847faf, 0x110eefda}}}}}
    };

    void fq2_multiply_by_u(Fq2& result, const Fq2& a) {
        Fq t;
        t.copy(a.c0);
        result.c0.negate(a.c1);
        result.c1.copy(t);
    }

    void fq2_multiply_frobenius(Fq2& result, const Fq2& a, unsigned int power) {
        result.copy(a);
        for (unsigned int i = 0; i != power; i++) {
            result.multiply(result, uplusonetotheqminusoneoversix);
        }
    }

    void G2::frobenius_map(const G2& a, unsigned int power) {
        switch (power & 0x3) {
        case 0:
            this->copy(a);
            break;
        case 1:
            this->x.frobenius_map(a.x, 1);
            this->y.frobenius_map(a.y, 1);
            this->z.frobenius_map(a.z, 1);

            fq2_multiply_frobenius(this->x, this->x, 4);
            fq2_multiply_by_u(this->x, this->x);
            fq2_multiply_by_u(this->y, this->y);
            fq2_multiply_frobenius(this->y, this->y, 3);
            break;
        case 2:
            // TODO
        case 3:
            // TODO
            break;
        }
    }

    /*
     * This method computes a^(c0 + c1*|x| + c2*|x|^2 + c3*|x|^3). It uses the
     * fact that r = x^4 - x^2 + 1 and q = (x - 1)^2 * r * 3^(-1) + x, which
     * implies that, if |a| = r (which is true for a in G2), then a^q = a^x.
     * Therefore, we can use the frobenius map to calculate a^x, speeding up
     * computation substantially (only one-fourth as many squares).
     */
    void G2::multiply_coeff(const G2& a, const BigInt<64>& c0, const BigInt<64>& c1, const BigInt<64>& c2, const BigInt<64>& c3) {
        const BigInt<64>* b[4] = {&c0, &c1, &c2, &c3};

        WnafScalar<64, 4> wb[4];
        for (unsigned int i = 0; i != 4; i++) {
            wb[i].from_bigint(*b[i]);
        }

        G2 t[4];
        t[0].copy(a);
        for (unsigned int i = 1; i != 4; i++) {
            /* Equivalent to t[i].multiply(t[i - 1], Fq::p_value); */
            t[i].frobenius_map(t[i - 1], 1);
        }
        for (unsigned int i = 0; i != 4; i++) {
            if (((i & 0x1) == 0) != bls_x_is_negative) {
                t[i].negate(t[i]);
            }
        }

        WnafTable<G2, 4> wt[4];
        for (unsigned int i = 0; i != 4; i++) {
            wt[i].fill_table(t[i]);
        }

        this->copy(G2::zero);
        bool found_one = false;
        for (int i = 64; i != -1; i--) {
            if (found_one) {
                this->multiply2(*this);
            }
            for (unsigned int j = 0; j != 4; j++) {
                /*
                 * Functionally, the code we want is:
                 * if (b[j]->bit(i)) {
                 *     this->add(*this, t[j]);
                 *     found_one = true;
                 * }
                 *
                 * The code below does the same thing, but uses w-NAF to speed
                 * it up.
                 */
                WnafScalar<64, 4>& power = wb[j];
                if (i < power.wnaf_size && power.wnaf[i] != 0) {
                    if (power.wnaf[i] > 0) {
                        this->add(*this, wt[j].table[power.wnaf[i] >> 1]);
                    } else {
                        Projective tmp;
                        tmp.negate(wt[j].table[(-power.wnaf[i]) >> 1]);
                        this->add(*this, tmp);
                    }
                    found_one = true;
                }
            }
        }
    }

    /*
     * Decomposes a chosen value y into c0, c1, c2, c3 such that each c is in
     * [0, |x|) and y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3. The argument y must
     * be in the interval [0, r).
     */
    static void div_exp_coeff(BigInt<64>& c0, BigInt<64>& c1, BigInt<64>& c2, BigInt<64>& c3, const BigInt<256>& y) {
        BigInt<256> quotient;

        constexpr BigInt<64>::word_t x = (BigInt<64>::word_t) (((uint64_t) bls_x.std_words[1]) << 32) | (uint64_t) (bls_x.std_words[0]);
        c0.words[0] = quotient.divide_word<x>(y);
        c1.words[0] = quotient.divide_word<x>(quotient);
        c2.words[0] = quotient.divide_word<x>(quotient);
        c3.words[0] = quotient.words[0];
    }

    /*
     * Sets this to a ^ power, using division to decompose power. This may not
     * be performant on systems where division is slow (e.g., systems that
     * do not have hardware division support, or systems that do not support
     * 64-bit words).
     */
    void G2::multiply_div(const G2& a, const BigInt<256>& scalar) {
        BigInt<64> c0, c1, c2, c3;
        if (BigInt<256>::compare(scalar, Fr::p_value) == -1) {
            div_exp_coeff(c0, c1, c2, c3, scalar);
        } else {
            BigInt<256> a;
            a.subtract(scalar, Fr::p_value);
            div_exp_coeff(c0, c1, c2, c3, a);
        }
        this->multiply_coeff(a, c0, c1, c2, c3);
    }
}
