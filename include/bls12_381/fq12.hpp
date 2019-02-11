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

#ifndef EMBEDDED_PAIRING_BLS12_381_FQ12_HPP_
#define EMBEDDED_PAIRING_BLS12_381_FQ12_HPP_

#include <stddef.h>

#include "./fq2.hpp"
#include "./fq6.hpp"

namespace embedded_pairing::bls12_381 {
    struct Fq12 {
        Fq6 c0;
        Fq6 c1;

        static const Fq12 one;
        static const Fq12 zero;

        bool is_zero(void) const;
        void copy(const Fq12& a);
        void add(const Fq12& a, const Fq12& __restrict b);
        void multiply2(const Fq12& a);
        void subtract(const Fq12& a, const Fq12& __restrict b);
        void negate(const Fq12& a);
        void inverse(const Fq12& a);
        void frobenius_map(const Fq12& a, unsigned int power);
        void multiply(const Fq12& a, const Fq12& b);
        void square(const Fq12& a);
        void multiply_by_c014(const Fq12& a, const Fq2& __restrict c0, const Fq2& __restrict c1, const Fq2& __restrict c4);
        void conjugate(const Fq12& a);
        void random(void (*get_random_bytes)(void*, size_t));
        void write_big_endian(uint8_t* buffer) const;
        void read_big_endian(const uint8_t* buffer);

        /*
         * Faster functions for the pairing target group GT, which is a
         * subgroup of the cyclotomic subgroup.
         */
        void square_cyclotomic(const Fq12& a);
        template <typename BigInt>
        void exponentiate_restrict_cyclotomic_nodiv(const Fq12& __restrict a, const BigInt& __restrict power) {
#ifdef RESIST_SIDE_CHANNELS
            Fq12 tmp;
#else
            bool found_one = false;
#endif
            this->copy(Fq12::one);
            for (int i = BigInt::bits_value - 1; i != -1; i--) {
#ifdef RESIST_SIDE_CHANNELS
                this->square_cyclotomic(*this);
                if (power.bit(i)) {
                    this->multiply(*this, a);
                } else {
                    tmp.multiply(*this, a);
                }
#else
                if (found_one) {
                    this->square_cyclotomic(*this);
                }
                if (power.bit(i)) {
                    this->multiply(*this, a);
                    found_one = true;
                }
#endif
            }
        }
        template <typename BigInt>
        void exponentiate_gt_nodiv(const Fq12& a, const BigInt& __restrict power) {
            Fq12 tmp;
            tmp.exponentiate_restrict_cyclotomic_nodiv<BigInt>(a, power);
            this->copy(tmp);
        }
        void exponentiate_gt(const Fq12& a, const BigInt<256>& power) {
            /*
             * Division to decompose into words should be faster if we have
             * support for 64-bit words.
             */
            if constexpr(sizeof(BigInt<256>::word_t) >= 8) {
                this->exponentiate_gt_div(a, power);
            } else {
                this->exponentiate_gt_nodiv(a, power);
            }
        }
        /* Sets this to a^((q^6 - 1)*(q^2 + 1)). */
        void map_to_cyclotomic(const Fq12& a);

        /*
         * This method computes a^(c0 + c1*|x| + c2*|x|^2 + c3*|x|^3). It uses the
         * fact that r = x^4 - x^2 + 1 and q = (x - 1)^2 * r * 3^(-1) + x, which
         * implies that, if |a| = r (which is true for a in GT), then a^q = a^x.
         * Therefore, we can use the frobenius map to calculate a^x, speeding up
         * computation substantially.
         */
        void exponentiate_gt_coeff(const Fq12& a, const BigInt<64>& c0, const BigInt<64>& c1, const BigInt<64>& c2, const BigInt<64>& c3);

        /*
         * Decomposes a chosen value y into c0, c1, c2, c3 such that each c is in
         * [0, |x|) and y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3. The argument y must
         * be in the interval [0, r).
         */
        static void div_exp_coeff(BigInt<64>& c0, BigInt<64>& c1, BigInt<64>& c2, BigInt<64>& c3, const BigInt<256>& y);

        /*
         * Sets this to a ^ power, using division to decompose power. This may not
         * be performant on systems where division is slow (e.g., systems that
         * do not have hardware division support, or systems that do not support
         * 64-bit words).
         */
        void exponentiate_gt_div(const Fq12& a, const BigInt<256>& power);

        /*
         * Chooses random c0, c1, c2, c3 such that each c is in [0, |x|) and
         * y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3 is uniformly distributed in
         * [0, r).
         */
        static void random_gt_exp_coeff(BigInt<256>& y, BigInt<64>& c0, BigInt<64>& c1, BigInt<64>& c2, BigInt<64>& c3, void (*get_random_bytes)(void*, size_t));

        /*
         * Chooses an exponent y uniformly distributed in [0, r) and computes
         * base^y. This is significantly faster than using exponentiate or
         * exponentiate_cyclotomic.
         */
        void random_gt(BigInt<256>& y, const Fq12& base, void (*get_random_bytes)(void*, size_t));

        static bool equal(const Fq12& a, const Fq12& b);
    };

    constexpr Fq12 Fq12::one = {.c0 = Fq6::one, .c1 = Fq6::zero};
    constexpr Fq12 Fq12::zero = {.c0 = Fq6::zero, .c1 = Fq6::zero};
}

#endif
