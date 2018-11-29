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
#include "bls12_381/fq2.hpp"
#include "bls12_381/fq12.hpp"
#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"

#include <stdio.h>

namespace embedded_pairing::bls12_381 {
    void miller_doubling_step(MillerTriple& result, G2& r) {
        Fq2& tmp0 = result.a;
        tmp0.square(r.x);

        Fq2 tmp1;
        tmp1.square(r.y);

        Fq2 tmp2;
        tmp2.square(tmp1);

        Fq2& tmp3 = result.b;
        tmp3.add(tmp1, r.x);
        tmp3.square(tmp3);
        tmp3.subtract(tmp3, tmp0);
        tmp3.subtract(tmp3, tmp2);
        tmp3.multiply2(tmp3);

        Fq2 tmp4;
        tmp4.multiply2(tmp0);
        tmp4.add(tmp4, tmp0);

        Fq2& tmp6 = result.c;
        tmp6.add(r.x, tmp4);

        Fq2 tmp5;
        tmp5.square(tmp4);

        Fq2 zsquared;
        zsquared.square(r.z);

        r.x.subtract(tmp5, tmp3);
        r.x.subtract(r.x, tmp3);

        r.z.add(r.z, r.y);
        r.z.square(r.z);
        r.z.subtract(r.z, tmp1);
        r.z.subtract(r.z, zsquared);

        r.y.subtract(tmp3, r.x);
        r.y.multiply(r.y, tmp4);

        tmp2.multiply2(tmp2);
        tmp2.multiply2(tmp2);
        tmp2.multiply2(tmp2);

        r.y.subtract(r.y, tmp2);

        // Calculate result.b
        tmp3.multiply(tmp4, zsquared);
        tmp3.multiply2(tmp3);
        tmp3.negate(tmp3);

        // Calculate result.c
        tmp6.square(tmp6);
        tmp6.subtract(tmp6, tmp0);
        tmp6.subtract(tmp6, tmp5);

        tmp1.multiply2(tmp1);
        tmp1.multiply2(tmp1);

        tmp6.subtract(tmp6, tmp1);

        // Calculate result.a
        tmp0.multiply(r.z, zsquared);
        tmp0.multiply2(tmp0);
    }

    void miller_addition_step(MillerTriple& result, G2& r, const G2Affine& g2) {
        Fq2 zsquared;
        zsquared.square(r.z);

        Fq2 ysquared;
        ysquared.square(g2.y);

        Fq2 t0;
        t0.multiply(zsquared, g2.x);

        Fq2& t1 = result.b;
        t1.add(g2.y, r.z);
        t1.square(t1);
        t1.subtract(t1, ysquared);
        t1.subtract(t1, zsquared);
        t1.multiply(t1, zsquared);

        Fq2 t2;
        t2.subtract(t0, r.x);

        Fq2 t3;
        t3.square(t2);

        Fq2 t4;
        t4.multiply2(t3);
        t4.multiply2(t4);

        Fq2 t5;
        t5.multiply(t4, t2);

        Fq2 t6;
        t6.subtract(t1, r.y);
        t6.subtract(t6, r.y);

        Fq2& t9 = result.c;
        t9.multiply(t6, g2.x);

        Fq2 t7;
        t7.multiply(t4, r.x);

        r.x.square(t6);
        r.x.subtract(r.x, t5);
        r.x.subtract(r.x, t7);
        r.x.subtract(r.x, t7);

        r.z.add(r.z, t2);
        r.z.square(r.z);
        r.z.subtract(r.z, zsquared);
        r.z.subtract(r.z, t3);

        Fq2& t10 = result.a;
        t10.add(g2.y, r.z);

        Fq2 t8;
        t8.subtract(t7, r.x);
        t8.multiply(t8, t6);

        t0.multiply(r.y, t5);
        t0.multiply2(t0);

        r.y.subtract(t8, t0);

        t10.square(t10);
        t10.subtract(t10, ysquared);

        Fq2 ztsquared;
        ztsquared.square(r.z);

        t10.subtract(t10, ztsquared);

        t9.multiply2(t9);
        t9.subtract(t9, t10);

        t10.multiply2(r.z);

        t6.negate(t6);

        t1.multiply2(t6);
    }

    void G2Prepared::prepare(const G2Affine& g2) {
        G2 r;
        r.from_affine(g2);
        int coeff_idx = 0;

        /* Skips the least significant bit and most significant set bit. */
        for (unsigned int i = bls_x_highest_set_bit - 1; i != 0; i--) {
            miller_doubling_step(this->coeffs[coeff_idx++], r);
            if (bls_x.bit(i)) {
                miller_addition_step(this->coeffs[coeff_idx++], r, g2);
            }
        }

        miller_doubling_step(this->coeffs[coeff_idx], r);
        this->infinity = g2.is_zero();
    }

    static void ell(Fq12& f, const MillerTriple& coeffs, const G1Affine& g1) {
        Fq2 c0;
        Fq2 c1;

        c0.c0.multiply(coeffs.a.c0, g1.y);
        c0.c1.multiply(coeffs.a.c1, g1.y);

        c1.c0.multiply(coeffs.b.c0, g1.x);
        c1.c1.multiply(coeffs.b.c1, g1.x);

        f.multiply_by_c014(f, coeffs.c, c1, c0);
    }

    void miller_loop(Fq12& result, AffinePair* pairs, unsigned int num_pairs) {
        MillerTriple coeffs;
        result.copy(Fq12::one);

        for (unsigned int j = 0; j != num_pairs; j++) {
            AffinePair& pair = pairs[j];
            pair.r.from_affine(*pair.g2);
        }

        /* Skips the least significant bit and most significant set bit. */
        for (unsigned int i = bls_x_highest_set_bit - 1; i != 0; i--) {
            for (unsigned int j = 0; j != num_pairs; j++) {
                AffinePair& pair = pairs[j];
                if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                    miller_doubling_step(coeffs, pair.r);
                    ell(result, coeffs, *pair.g1);
                }
            }

            if (bls_x.bit(i)) {
                for (unsigned int j = 0; j != num_pairs; j++) {
                    AffinePair& pair = pairs[j];
                    if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                        miller_addition_step(coeffs, pair.r, *pair.g2);
                        ell(result, coeffs, *pair.g1);
                    }
                }
            }

            result.square(result);
        }

        for (unsigned int j = 0; j != num_pairs; j++) {
            AffinePair& pair = pairs[j];
            if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                miller_doubling_step(coeffs, pair.r);
                ell(result, coeffs, *pair.g1);
            }
        }

        if constexpr(bls_x_is_negative) {
            result.conjugate(result);
        }
    }

    void miller_loop(Fq12& result, const G1Affine& g1, const G2Affine& g2) {
        AffinePair pair;
        pair.g1 = &g1;
        pair.g2 = &g2;
        miller_loop(result, &pair, 1);
    }

    void miller_loop(Fq12& result, PreparedPair* pairs, unsigned int num_pairs) {
        result.copy(Fq12::one);

        for (unsigned int j = 0; j != num_pairs; j++) {
            PreparedPair& pair = pairs[j];
            pair.coeff_idx = 0;
        }

        /* Skips the least significant bit and most significant set bit. */
        for (unsigned int i = bls_x_highest_set_bit - 1; i != 0; i--) {
            for (unsigned int j = 0; j != num_pairs; j++) {
                PreparedPair& pair = pairs[j];
                if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                    ell(result, pair.g2->coeffs[pair.coeff_idx++], *pair.g1);
                }
            }
            if (bls_x.bit(i)) {
                for (unsigned int j = 0; j != num_pairs; j++) {
                    PreparedPair& pair = pairs[j];
                    if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                        ell(result, pair.g2->coeffs[pair.coeff_idx++], *pair.g1);
                    }
                }
            }
            result.square(result);
        }

        for (unsigned int j = 0; j != num_pairs; j++) {
            PreparedPair& pair = pairs[j];
            if (!pair.g1->is_zero() && !pair.g2->is_zero()) {
                ell(result, pair.g2->coeffs[pair.coeff_idx++], *pair.g1);
            }
        }

        if constexpr(bls_x_is_negative) {
            result.conjugate(result);
        }
    }

    void miller_loop(Fq12& result, const G1Affine& g1, const G2Prepared& g2) {
        PreparedPair pair;
        pair.g1 = &g1;
        pair.g2 = &g2;
        miller_loop(result, &pair, 1);
    }

    /*
     * There is no benefit to being constant time in the exponent, since
     * "bls_x" is assumed to be publicly known.
     */
    template <unsigned int right_shift, bool square_at_end>
    static inline void exp_by_x_restrict(Fq12& result, const Fq12& a) {
        result.copy(Fq12::one);

        for (int i = bls_x_highest_set_bit; i != right_shift - 1; i--) {
            result.square(result);
            if (bls_x.bit(i)) {
                result.multiply(result, a);
            }
        }

        if constexpr(square_at_end) {
            result.square(result);
        }

        if constexpr(bls_x_is_negative) {
            result.conjugate(result);
        }
    }

    void final_exponentiation(Fq12& result, const Fq12& a) {
        Fq12 f1;
        f1.conjugate(a);

        Fq12 f2;
        f2.inverse(a);
        Fq12 r;
        r.multiply(f1, f2);
        f2.copy(r);
        r.frobenius_map(r, 2);
        r.multiply(r, f2);

        Fq12 y0;
        y0.square(r);

        Fq12& y1 = result;
        exp_by_x_restrict<0, false>(y1, y0);

        Fq12 y2;
        exp_by_x_restrict<1, false>(y2, y1);

        Fq12 y3;
        y3.conjugate(r);
        y1.multiply(y1, y3);
        y1.conjugate(y1);
        y1.multiply(y1, y2);
        exp_by_x_restrict<1, true>(y2, y1);
        exp_by_x_restrict<1, true>(y3, y2);
        y1.conjugate(y1);
        y3.multiply(y3, y1);
        y1.conjugate(y1);
        y1.frobenius_map(y1, 3);
        y2.frobenius_map(y2, 2);
        y1.multiply(y1, y2);
        exp_by_x_restrict<1, true>(y2, y3);
        y2.multiply(y2, y0);
        y2.multiply(y2, r);
        y1.multiply(y1, y2);
        y2.frobenius_map(y3, 1);
        y1.multiply(y1, y2);
    }
}
