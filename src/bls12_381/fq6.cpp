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

#include "bls12_381/fq2.hpp"
#include "bls12_381/fq6.hpp"

namespace embedded_pairing::bls12_381 {
    static constexpr Fq2 fq6_frobenius_coeff_c1[6] = {
        {
            {{{{.std_words = {0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}},
            {{{{.std_words = {0x8671f071, 0xcd03c9e4, 0x1fcda5d2, 0x5dab2246, 0xd3851b95, 0x587042af, 0x1bacb9e, 0x8eb60ebe, 0x83d050d2, 0x3f97d6e, 0x54638741, 0x18f02065}}}}}
        },
        {
            {{{{.std_words = {0x798a64e8, 0x30f1361b, 0x7ece5a2a, 0xf3b8ddab, 0xc61577f7, 0x16a8ca3a, 0x74fd029b, 0xc26a2ff8, 0x60701c6e, 0x3636b766, 0x241b6160, 0x51ba4ab}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}},
            {{{{.std_words = {0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3}}}}}
        },
        {
            {{{{.std_words = {0x8671f071, 0xcd03c9e4, 0x1fcda5d2, 0x5dab2246, 0xd3851b95, 0x587042af, 0x1bacb9e, 0x8eb60ebe, 0x83d050d2, 0x3f97d6e, 0x54638741, 0x18f02065}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}},
            {{{{.std_words = {0x798a64e8, 0x30f1361b, 0x7ece5a2a, 0xf3b8ddab, 0xc61577f7, 0x16a8ca3a, 0x74fd029b, 0xc26a2ff8, 0x60701c6e, 0x3636b766, 0x241b6160, 0x51ba4ab}}}}}
        }
    };
    static constexpr Fq2 fq6_frobenius_coeff_c2[6] = {
        {
            {{{{.std_words = {0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x867545c3, 0x890dc9e4, 0x3285a5d5, 0x2af32253, 0x309b7e2c, 0x50880866, 0x7e881024, 0xa20d1b8c, 0xe2db9068, 0x14e4f04f, 0x1564853a, 0x14e56d3f}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x8671f071, 0xcd03c9e4, 0x1fcda5d2, 0x5dab2246, 0xd3851b95, 0x587042af, 0x1bacb9e, 0x8eb60ebe, 0x83d050d2, 0x3f97d6e, 0x54638741, 0x18f02065}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0xfffcaaae, 0x43f5ffff, 0xed47fffd, 0x32b7fff2, 0xa2e99d69, 0x7e83a49, 0x8332bb7a, 0xeca8f331, 0xa0f4c069, 0xef148d1e, 0x3eff0206, 0x40ab326}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x798a64e8, 0x30f1361b, 0x7ece5a2a, 0xf3b8ddab, 0xc61577f7, 0x16a8ca3a, 0x74fd029b, 0xc26a2ff8, 0x60701c6e, 0x3636b766, 0x241b6160, 0x51ba4ab}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x798dba3a, 0xecfb361b, 0x91865a2c, 0xc100ddb8, 0x232bda8e, 0xec08ff1, 0xf1ca4721, 0xd5c13cc6, 0xbf7b5c04, 0x47222a47, 0xe51c5f59, 0x110f184}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        }
    };

    bool Fq6::is_zero(void) const {
        bool c0_zero = this->c0.is_zero();
        bool c1_zero = this->c1.is_zero();
        bool c2_zero = this->c2.is_zero();
        return c0_zero && c1_zero && c2_zero;
    }

    void Fq6::copy(const Fq6& a) {
        this->c0.copy(a.c0);
        this->c1.copy(a.c1);
        this->c2.copy(a.c2);
    }

    void Fq6::add(const Fq6& a, const Fq6& __restrict b) {
        this->c0.add(a.c0, b.c0);
        this->c1.add(a.c1, b.c1);
        this->c2.add(a.c2, b.c2);
    }

    void Fq6::multiply2(const Fq6& a) {
        this->c0.multiply2(a.c0);
        this->c1.multiply2(a.c1);
        this->c2.multiply2(a.c2);
    }

    void Fq6::subtract(const Fq6& a, const Fq6& __restrict b) {
        this->c0.subtract(a.c0, b.c0);
        this->c1.subtract(a.c1, b.c1);
        this->c2.subtract(a.c2, b.c2);
    }

    void Fq6::negate(const Fq6& a) {
        this->c0.negate(a.c0);
        this->c1.negate(a.c1);
        this->c2.negate(a.c2);
    }

    void Fq6::inverse(const Fq6& a) {
        Fq2 t0;

        Fq2 c0;
        c0.multiply_by_nonresidue(a.c2);
        c0.multiply(c0, a.c1);
        c0.negate(c0);
        t0.square(a.c0);
        c0.add(c0, t0);

        Fq2 c1;
        c1.square(a.c2);
        c1.multiply_by_nonresidue(c1);
        t0.multiply(a.c0, a.c1);
        c1.subtract(c1, t0);

        Fq2 c2;
        c2.square(a.c1);
        t0.multiply(a.c0, a.c2);
        c2.subtract(c2, t0);

        Fq2 t1;
        t1.multiply(a.c2, c1);
        t0.multiply(a.c1, c2);
        t1.add(t1, t0);
        t1.multiply_by_nonresidue(t1);
        t0.multiply(a.c0, c0);
        t1.add(t1, t0);

        t0.inverse(t1);
        this->c0.multiply(c0, t0);
        this->c1.multiply(c1, t0);
        this->c2.multiply(c2, t0);
    }

    void Fq6::frobenius_map(const Fq6& a, unsigned int power) {
        this->c0.frobenius_map(a.c0, power);
        this->c1.frobenius_map(a.c1, power);
        this->c2.frobenius_map(a.c2, power);

        unsigned int coeff_idx = power % 6;
        this->c1.multiply(this->c1, fq6_frobenius_coeff_c1[coeff_idx]);
        this->c2.multiply(this->c2, fq6_frobenius_coeff_c2[coeff_idx]);
    }

    void Fq6::multiply(const Fq6& a, const Fq6& b) {
        Fq2 a_a;
        Fq2 b_b;
        Fq2 c_c;
        a_a.multiply(a.c0, b.c0);
        b_b.multiply(a.c1, b.c1);
        c_c.multiply(a.c2, b.c2);

        Fq2 tmp1;
        Fq2 tmp2;
        Fq2 tmp3;
        tmp1.add(a.c1, a.c2);
        tmp2.add(a.c0, a.c1);
        tmp3.add(a.c0, a.c2);

        this->c0.add(b.c1, b.c2);
        this->c0.multiply(this->c0, tmp1);
        this->c0.subtract(this->c0, b_b);
        this->c0.subtract(this->c0, c_c);
        this->c0.multiply_by_nonresidue(this->c0);
        this->c0.add(this->c0, a_a);

        this->c2.add(b.c0, b.c2);
        this->c2.multiply(this->c2, tmp3);
        this->c2.subtract(this->c2, a_a);
        this->c2.add(this->c2, b_b);
        this->c2.subtract(this->c2, c_c);

        this->c1.add(b.c0, b.c1);
        this->c1.multiply(this->c1, tmp2);
        this->c1.subtract(this->c1, a_a);
        this->c1.subtract(this->c1, b_b);
        c_c.multiply_by_nonresidue(c_c);
        this->c1.add(this->c1, c_c);
    }

    void Fq6::square(const Fq6& a) {
        Fq2 s0;
        s0.square(a.c0);

        Fq2 s1;
        s1.multiply(a.c0, a.c1);
        s1.multiply2(s1);

        Fq2 s2;
        s2.subtract(a.c0, a.c1);
        s2.add(s2, a.c2);
        s2.square(s2);

        Fq2 s3;
        s3.multiply(a.c1, a.c2);
        s3.multiply2(s3);

        Fq2 s4;
        s4.square(a.c2);

        this->c0.multiply_by_nonresidue(s3);
        this->c0.add(this->c0, s0);

        this->c1.multiply_by_nonresidue(s4);
        this->c1.add(this->c1, s1);

        this->c2.add(s1, s2);
        this->c2.add(this->c2, s3);
        this->c2.subtract(this->c2, s0);
        this->c2.subtract(this->c2, s4);
    }

    void Fq6::multiply_by_nonresidue(const Fq6& a) {
        Fq2 t0;
        t0.copy(a.c0);
        this->c0.multiply_by_nonresidue(a.c2);
        this->c2.copy(a.c1);
        this->c1.copy(t0);
    }

    void Fq6::multiply_by_c1(const Fq6& a, const Fq2& __restrict c1) {
        Fq2 tmp1;
        Fq2 tmp2;
        tmp1.add(a.c1, a.c2);
        tmp2.add(a.c0, a.c1);

        this->c2.multiply(a.c1, c1);

        this->c0.multiply(c1, tmp1);
        this->c0.subtract(this->c0, this->c2);
        this->c0.multiply_by_nonresidue(this->c0);

        this->c1.multiply(c1, tmp2);
        this->c1.subtract(this->c1, this->c2);
    }

    void Fq6::multiply_by_c01(const Fq6& a, const Fq2& __restrict c0, const Fq2& __restrict c1) {
        Fq2 tmp1;
        Fq2 tmp2;
        Fq2 tmp3;
        tmp1.add(a.c1, a.c2);
        tmp2.add(a.c0, a.c1);
        tmp3.add(a.c0, a.c2);

        Fq2 a_a;
        Fq2 b_b;
        a_a.multiply(a.c0, c0);
        b_b.multiply(a.c1, c1);

        this->c0.multiply(c1, tmp1);
        this->c0.subtract(this->c0, b_b);
        this->c0.multiply_by_nonresidue(this->c0);
        this->c0.add(this->c0, a_a);

        this->c1.add(c0, c1);
        this->c1.multiply(this->c1, tmp2);
        this->c1.subtract(this->c1, a_a);
        this->c1.subtract(this->c1, b_b);

        this->c2.multiply(c0, tmp3);
        this->c2.subtract(this->c2, a_a);
        this->c2.add(this->c2, b_b);
    }

    void Fq6::random(void (*get_random_bytes)(void*, size_t)) {
        this->c0.random(get_random_bytes);
        this->c1.random(get_random_bytes);
        this->c2.random(get_random_bytes);
    }

    bool Fq6::equal(const Fq6& a, const Fq6& b) {
        bool c0_equal = Fq2::equal(a.c0, b.c0);
        bool c1_equal = Fq2::equal(a.c1, b.c1);
        bool c2_equal = Fq2::equal(a.c2, b.c2);
        return c0_equal && c1_equal && c2_equal;
    }
}
