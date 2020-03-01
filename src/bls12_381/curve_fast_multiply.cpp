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
    BigInt<256> g1_endomorphism_lambda = {
        .std_words = {0x00000001, 0xfffffffe, 0xfffcb7fc, 0xa7780001, 0x09a1d804, 0x3339d808, 0x299d7d48, 0x73eda753}
    };

    /*
     * This value divided by 2^(384+254) is an approximation of 1/Fr::p_value.
     * In Theorem 4.2 of https://gmplib.org/~tege/divcnst-pldi94.pdf, this is
     * the constant m for d = Fr::p_value, N = 384, and l = 254.
     */
    static constexpr BigInt<384> fr_p_value_reciprocal = {
        .std_words = {0xfc75349a, 0xf6dee1ae, 0x9115e163, 0xc40584f3, 0x830358e4, 0x509cde80, 0x2f92eb5c, 0xd9410fad, 0xc1f823b4, 0x0e2d772d, 0x7fb78ddf, 0x8d54253b}
    };

    /*
     * v1 = <1, -v1_2> and v2 = <v2_1, 1> are two linearly independent vectors
     * such that f(v1) = f(v2) = 0, where f(<x, y>) = x + lambda * y.
     */
    static constexpr BigInt<128> g1_v1_2 = {
        .std_words = {0xffffffff, 0x00000000, 0x0001a402, 0xac45a401}
    };
    static constexpr BigInt<128> g1_v2_1 = {
        .std_words = {0x00000000, 0x00000001, 0x0001a402, 0xac45a401}
    };
    static constexpr Fq g1_endomorphism_beta = {
        {{{.std_words = {0x798a64e8, 0x30f1361b, 0x7ece5a2a, 0xf3b8ddab, 0xc61577f7, 0x16a8ca3a, 0x74fd029b, 0xc26a2ff8, 0x60701c6e, 0x3636b766, 0x241b6160, 0x051ba4ab}}}}
    };
    static constexpr Fq2 uplusonetotheqminusoneoversix = {
        {{{{.std_words = {0xb319d465, 0x7089552, 0xb50a8313, 0xc6695f92, 0xd117228f, 0x97e83ccc, 0xb2dc29ee, 0xa35baeca, 0x5daace4d, 0x1ce393ea, 0xb0fb66eb, 0x8f2220f}}}}},
        {{{{.std_words = {0x4ce5d646, 0xb2f66aad, 0xfc497cec, 0x5842a06b, 0x2599d394, 0xcf4895d4, 0x40a8e8d0, 0xc11b9cba, 0xe5a0de89, 0x2e3813cb, 0x88847faf, 0x110eefda}}}}}
    };

    /*
     * Uses Theorem 4.2 in https://gmplib.org/~tege/divcnst-pldi94.pdf. The
     * result could have up to 130 bits in general.
     */
    template <int result_bits>
    static void floordiv_by_fr_p_value(BigInt<result_bits>& result, const BigInt<384> divisor) {
        BigInt<768> divisortimesreciprocal;
        divisortimesreciprocal.multiply(divisor, fr_p_value_reciprocal);
        divisortimesreciprocal.shift_right(divisortimesreciprocal, 384+254);
        result.copy(divisortimesreciprocal);
    }

    /*
     * Decomposes a chosen value y into c0, c1 such that
     * k = c0 + c1*lambda (mod r) where c0 and c1 have half as many bits as y
     * and r is the order of the group. The argument y must be in the interval
     * [0, r).
     *
     * The algorithm used is presented in Section 4 of the following paper:
     * R. P. Gallant, R. J. Lambert, and S. A. Vanstone. Faster Point
     * Multiplication on Elliptic Curves with Efficient Endomorphisms. CRYPTO
     * 2001.
     */
    void decompose_lambda(BigInt<256>& c0, bool& c0_neg, BigInt<256>& c1, bool& c1_neg, const BigInt<256>& k) {
        /*
         * We can write <k, 0> = b1 * v1 + b2 * v2, where:
         * b1 = k / (1 + v1_2 * v2_1) and b2 = v1_2 * k / (1 + v1_2 * v2_1).
         * Observe that Fr::p_value == (1 + v1_2 * v2_1), so we don't have to
         * compute that value.
         * Then we take <c0, c1> = <k, 0> - (round(b1) * v1 + round(b2) * v2).
         */

         /* First, we compute round(b1) and store it in rounded_b1. */
         int rounded_b1;
         BigInt<256> two_k;
         if (two_k.shift_left_in_word<1>(k) != 0) {
             rounded_b1 = 1;
         } else if (BigInt<256>::compare(two_k, Fr::p_value) == -1) {
             rounded_b1 = 0;
         } else {
             rounded_b1 = 1;
         }

         /* Second, we compute round(b2) and store it in rounded_b2. */
         BigInt<128> rounded_b2;
         BigInt<384> v1_2timesk;
         v1_2timesk.multiply(g1_v1_2, k);
         floordiv_by_fr_p_value(rounded_b2, v1_2timesk);
         /*
          * Although rounded_b2_wide has up to 130 bits for an arbitrary
          * division by Fr::p_value, we can bound it to 128 bits for this
          * particular division because k and v1_2 are both in [0, r).
          */

         /* Third, we compute c0 = k - rounded_b1 - rounded_b2 * v2_1. */
         BigInt<256> product;
         product.multiply(rounded_b2, g1_v2_1);
         if (rounded_b1 == 1) {
             BigInt<256> one = {.std_words = {1, 0, 0, 0, 0, 0, 0, 0}};
             product.add(product, one);
         }
         if (BigInt<256>::compare(k, product) == -1) {
             c0_neg = true;
             c0.subtract(product, k);
         } else {
             c0_neg = false;
             c0.subtract(k, product);
         }

         /* Fourth, we compute c1 = rounded_b1 * v1_2 - rounded_b2. */
         if (rounded_b1 == 0) {
             c1_neg = true;
             c1.copy(rounded_b2);
         } else {
             BigInt<256> v1_2_wide;
             BigInt<256> rounded_b2_wide;
             v1_2_wide.copy(g1_v1_2);
             rounded_b2_wide.copy(rounded_b2);
             if (BigInt<256>::compare(v1_2_wide, rounded_b2_wide) == -1) {
                 c1_neg = true;
                 c1.subtract(rounded_b2_wide, v1_2_wide);
             } else {
                 c1_neg = false;
                 c1.subtract(v1_2_wide, rounded_b2_wide);
             }
         }
    }

    void G1::endomorphism(const G1& a) {
        this->x.multiply(a.x, g1_endomorphism_beta);
        this->y.copy(a.y);
        this->z.copy(a.z);
    }

    void G1::multiply_endomorphism(const G1& a, const BigInt<256>& c0, bool c0_neg, const BigInt<256>& c1, bool c1_neg) {
        WnafScalar<256, 4> wc0;
        wc0.from_bigint(c0);
        WnafScalar<256, 4> wc1;
        wc1.from_bigint(c1);

        int larger_wnaf_size;
        if (wc0.wnaf_size < wc1.wnaf_size) {
            larger_wnaf_size = wc1.wnaf_size;
        } else {
            larger_wnaf_size = wc0.wnaf_size;
        }

        WnafTable<G1, 4> wt;
        wt.fill_table(a);

        this->copy(G1::zero);
        bool found_one = false;
        for (int i = larger_wnaf_size - 1; i != -1; i--) {
            if (found_one) {
                this->multiply2(*this);
            }

            /*
             * Functionally, the code we want is:
             * if (c0.bit(i)) {
             *     if (c0_neg) {
             *         G1 nega;
             *         nega.negate(a);
             *         this->add(*this, nega);
             *     } else {
             *         this->add(*this, a);
             *     }
             *     found_one = true;
             * }
             * if (c1.bit(i)) {
             *     G1 atimeslambda;
             *     atimeslambda.endomorphism(a);
             *     if (c1_neg) {
             *         atimeslambda.negate(atimeslambda);
             *     }
             *     this->add(*this, atimeslambda);
             *     found_one = true;
             * }
             *
             * The code below does the same thing, but uses w-NAF to speed
             * it up.
             */

            if (i < wc0.wnaf_size && wc0.wnaf[i] != 0) {
                if (wc0.wnaf[i] > 0) {
                    G1& entry = wt.table[wc0.wnaf[i] >> 1];
                    if (c0_neg) {
                        G1 tmp;
                        tmp.negate(entry);
                        this->add(*this, tmp);
                    } else {
                        this->add(*this, entry);
                    }
                } else {
                    G1& entry = wt.table[(-wc0.wnaf[i]) >> 1];
                    if (c0_neg) {
                        this->add(*this, entry);
                    } else {
                        G1 tmp;
                        tmp.negate(entry);
                        this->add(*this, tmp);
                    }
                }
                found_one = true;
            }

            if (i < wc1.wnaf_size && wc1.wnaf[i] != 0) {
                if (wc1.wnaf[i] > 0) {
                    G1 timeslambda;
                    timeslambda.endomorphism(wt.table[wc1.wnaf[i] >> 1]);
                    if (c1_neg) {
                        timeslambda.negate(timeslambda);
                    }
                    this->add(*this, timeslambda);
                } else {
                    G1 timeslambda;
                    timeslambda.endomorphism(wt.table[(-wc1.wnaf[i]) >> 1]);
                    if (!c1_neg) {
                        timeslambda.negate(timeslambda);
                    }
                    this->add(*this, timeslambda);
                }
                found_one = true;
            }
        }
    }

    void G1::multiply_fast(const G1& a, const BigInt<256>& scalar) {
        BigInt<256> c0, c1;
        bool c0_neg, c1_neg;
        if (BigInt<256>::compare(scalar, Fr::p_value) == -1) {
            decompose_lambda(c0, c0_neg, c1, c1_neg, scalar);
        } else {
            BigInt<256> a;
            a.subtract(scalar, Fr::p_value);
            decompose_lambda(c0, c0_neg, c1, c1_neg, scalar);
        }

        this->multiply_endomorphism(a, c0, c0_neg, c1, c1_neg);
    }

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
                        G2 tmp;
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
