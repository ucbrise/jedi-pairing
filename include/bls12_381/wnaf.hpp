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

#ifndef EMBEDDED_PAIRING_BLS12_381_WNAF_HPP_
#define EMBEDDED_PAIRING_BLS12_381_WNAF_HPP_

#include <stdint.h>

namespace embedded_pairing::bls12_381 {
    template <typename Projective, unsigned int window>
    struct WnafTable {
        static constexpr int table_size = 1 << (window - 1);
        Projective table[table_size];

        template <typename Base>
        void fill_table(const Base& base) {
            Projective two_base;

            table[0].set(base);
            two_base.multiply2(table[0]);
            for (int i = 1; i != table_size; i++) {
                table[i].add(table[i - 1], two_base);
            }
        }
    };

    /* This probably doesn't work for window >= 8 */
    template <int bits, unsigned int window>
    struct WnafScalar {
        int8_t wnaf[bits + 1];
        int wnaf_size;

        void from_bigint(const BigInt<bits>& scalar) {
            BigInt<bits> c;
            BigInt<bits> a;
            c.copy(scalar);
            a.clear();

            int i = 0;
            int16_t u;
            while (!c.is_zero()) {
                if (c.is_odd()) {
                    u = (int16_t) (c.bytes[0] & ((1 << (window + 1)) - 1));

                    if (u > (1 << window)) {
                        u -= (1 << (window + 1));
                    }

                    if (u > 0) {
                        a.bytes[0] = (uint8_t) u;
                        c.subtract(c, a);
                    } else {
                        a.bytes[0] = (uint8_t) (-u);
                        c.add(c, a);
                    }
                } else {
                    u = 0;
                }

                wnaf[i++] = (int8_t) u;
                c.template shift_right_in_word<1>(c);
            }
            wnaf_size = i;
        }
    };

    template <typename Projective, int bits, unsigned int window>
    void wnaf_table_multiply(Projective& result, const WnafTable<Projective, window>& table, const WnafScalar<bits, window>& power) {
        result.copy(Projective::zero);

        bool found_one = false;

        for (int i = power.wnaf_size - 1; i != -1; i--) {
            if (found_one) {
                result.multiply2(result);
            }

            if (power.wnaf[i] != 0) {
                if (power.wnaf[i] > 0) {
                    result.add(result, table.table[power.wnaf[i] >> 1]);
                } else {
                    Projective tmp;
                    tmp.negate(table.table[(-power.wnaf[i]) >> 1]);
                    result.add(result, tmp);
                }
                found_one = true;
            }
        }
    }

    template <typename Projective, typename Base, int bits, unsigned int window = 4>
    void wnaf_multiply(Projective& result, const Base& a, const BigInt<bits>& power) {
        WnafTable<Projective, window> t;
        t.fill_table(a);

        WnafScalar<bits, window> s;
        s.from_bigint(power);

        wnaf_table_multiply(result, t, s);
    }

    template <typename Projective, typename Base, int bits, unsigned int window>
    void wnaf_multiply(Projective& result, const Base& a, const WnafScalar<bits, window>& power) {
        WnafTable<Projective, window> t;
        t.fill_table(a);

        wnaf_table_multiply(result, t, power);
    }

    template <typename Projective, typename Base, int bits, unsigned int window>
    void wnaf_multiply(Projective& result, const WnafTable<Projective, window>& a, const BigInt<bits>& power) {
        WnafScalar<bits, window> s;
        s.from_bigint(power);

        wnaf_table_multiply(result, a, s);
    }
}

#endif
