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
#include "bls12_381/fq12.hpp"

namespace embedded_pairing::bls12_381 {
    static constexpr Fq2 fq12_frobenius_coeff_c1[12] = {
        {
            {{{{.std_words = {0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0xb319d465, 0x7089552, 0xb50a8313, 0xc6695f92, 0xd117228f, 0x97e83ccc, 0xb2dc29ee, 0xa35baeca, 0x5daace4d, 0x1ce393ea, 0xb0fb66eb, 0x8f2220f}}}}},
            {{{{.std_words = {0x4ce5d646, 0xb2f66aad, 0xfc497cec, 0x5842a06b, 0x2599d394, 0xcf4895d4, 0x40a8e8d0, 0xc11b9cba, 0xe5a0de89, 0x2e3813cb, 0x88847faf, 0x110eefda}}}}}
        },
        {
            {{{{.std_words = {0x798dba3a, 0xecfb361b, 0x91865a2c, 0xc100ddb8, 0x232bda8e, 0xec08ff1, 0xf1ca4721, 0xd5c13cc6, 0xbf7b5c04, 0x47222a47, 0xe51c5f59, 0x110f184}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0xa55c9ad1, 0x3e2f585d, 0x86c18183, 0x4294213d, 0x8b623732, 0x382844c8, 0x19103e18, 0x92ad2afd, 0xac7cf0b9, 0x1d794e4f, 0x7d825ec8, 0xbd592fc}}}}},
            {{{{.std_words = {0x5aa30fda, 0x7bcfa7a2, 0x2a927e7c, 0xdc17dec1, 0x6b4ebef1, 0x2f088dd8, 0xda74d4a7, 0xd1ca2087, 0x96cebc1d, 0x2da25966, 0xbbfd87d2, 0xe2b7eed}}}}}
        },
        {
            {{{{.std_words = {0x798a64e8, 0x30f1361b, 0x7ece5a2a, 0xf3b8ddab, 0xc61577f7, 0x16a8ca3a, 0x74fd029b, 0xc26a2ff8, 0x60701c6e, 0x3636b766, 0x241b6160, 0x51ba4ab}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0xf242c66c, 0x3726c30a, 0xd1b6fe70, 0x7c2ac1aa, 0xba4b14a2, 0xa04007fb, 0x66341429, 0xef517c32, 0x4ed2226b, 0x95ba65, 0xcc86f7dd, 0x2e370ec}}}}},
            {{{{.std_words = {0xdbce43f, 0x82d83cf5, 0xdf9d018f, 0xa2813e53, 0x3c65e181, 0xc6f0caa5, 0x8d50fe95, 0x7525cf52, 0xf4798a6b, 0x4a85ed50, 0x6cf8eebd, 0x171da0fd}}}}}
        },
        {
            {{{{.std_words = {0xfffcaaae, 0x43f5ffff, 0xed47fffd, 0x32b7fff2, 0xa2e99d69, 0x7e83a49, 0x8332bb7a, 0xeca8f331, 0xa0f4c069, 0xef148d1e, 0x3eff0206, 0x40ab326}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x4ce5d646, 0xb2f66aad, 0xfc497cec, 0x5842a06b, 0x2599d394, 0xcf4895d4, 0x40a8e8d0, 0xc11b9cba, 0xe5a0de89, 0x2e3813cb, 0x88847faf, 0x110eefda}}}}},
            {{{{.std_words = {0xb319d465, 0x7089552, 0xb50a8313, 0xc6695f92, 0xd117228f, 0x97e83ccc, 0xb2dc29ee, 0xa35baeca, 0x5daace4d, 0x1ce393ea, 0xb0fb66eb, 0x8f2220f}}}}}
        },
        {
            {{{{.std_words = {0x8671f071, 0xcd03c9e4, 0x1fcda5d2, 0x5dab2246, 0xd3851b95, 0x587042af, 0x1bacb9e, 0x8eb60ebe, 0x83d050d2, 0x3f97d6e, 0x54638741, 0x18f02065}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0x5aa30fda, 0x7bcfa7a2, 0x2a927e7c, 0xdc17dec1, 0x6b4ebef1, 0x2f088dd8, 0xda74d4a7, 0xd1ca2087, 0x96cebc1d, 0x2da25966, 0xbbfd87d2, 0xe2b7eed}}}}},
            {{{{.std_words = {0xa55c9ad1, 0x3e2f585d, 0x86c18183, 0x4294213d, 0x8b623732, 0x382844c8, 0x19103e18, 0x92ad2afd, 0xac7cf0b9, 0x1d794e4f, 0x7d825ec8, 0xbd592fc}}}}}
        },
        {
            {{{{.std_words = {0x867545c3, 0x890dc9e4, 0x3285a5d5, 0x2af32253, 0x309b7e2c, 0x50880866, 0x7e881024, 0xa20d1b8c, 0xe2db9068, 0x14e4f04f, 0x1564853a, 0x14e56d3f}}}}},
            {{{{.std_words = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0}}}}}
        },
        {
            {{{{.std_words = {0xdbce43f, 0x82d83cf5, 0xdf9d018f, 0xa2813e53, 0x3c65e181, 0xc6f0caa5, 0x8d50fe95, 0x7525cf52, 0xf4798a6b, 0x4a85ed50, 0x6cf8eebd, 0x171da0fd}}}}},
            {{{{.std_words = {0xf242c66c, 0x3726c30a, 0xd1b6fe70, 0x7c2ac1aa, 0xba4b14a2, 0xa04007fb, 0x66341429, 0xef517c32, 0x4ed2226b, 0x95ba65, 0xcc86f7dd, 0x2e370ec}}}}}
        }
    };

    bool Fq12::is_zero(void) const {
        bool c0_zero = this->c0.is_zero();
        bool c1_zero = this->c1.is_zero();
        return c0_zero && c1_zero;
    }

    void Fq12::copy(const Fq12& a) {
        this->c0.copy(a.c0);
        this->c1.copy(a.c1);
    }

    void Fq12::add(const Fq12& a, const Fq12& __restrict b) {
        this->c0.add(a.c0, b.c0);
        this->c1.add(a.c1, b.c1);
    }

    void Fq12::multiply2(const Fq12& a) {
        this->c0.multiply2(a.c0);
        this->c1.multiply2(a.c1);
    }

    void Fq12::subtract(const Fq12& a, const Fq12& __restrict b) {
        this->c0.subtract(a.c0, b.c0);
        this->c1.subtract(a.c1, b.c1);
    }

    void Fq12::negate(const Fq12& a) {
        this->c0.negate(a.c0);
        this->c1.negate(a.c1);
    }

    void Fq12::inverse(const Fq12& a) {
        Fq6 t0;
        Fq6 t1;
        t0.square(a.c0);
        t1.square(a.c1);
        t1.multiply_by_nonresidue(t1);
        t0.subtract(t0, t1);

        t1.inverse(t0);
        this->c0.multiply(a.c0, t1);
        this->c1.multiply(a.c1, t1);
        this->c1.negate(this->c1);
    }

    void Fq12::frobenius_map(const Fq12& a, unsigned int power) {
        this->c0.frobenius_map(a.c0, power);
        this->c1.frobenius_map(a.c1, power);

        unsigned int coeff_idx = power < 12 ? power : power % 12;
        this->c1.c0.multiply(this->c1.c0, fq12_frobenius_coeff_c1[coeff_idx]);
        this->c1.c1.multiply(this->c1.c1, fq12_frobenius_coeff_c1[coeff_idx]);
        this->c1.c2.multiply(this->c1.c2, fq12_frobenius_coeff_c1[coeff_idx]);
    }

    void Fq12::multiply(const Fq12& a, const Fq12& b) {
        Fq6 aa;
        Fq6 bb;
        Fq6 o;
        aa.multiply(a.c0, b.c0);
        bb.multiply(a.c1, b.c1);
        o.add(b.c0, b.c1);

        this->c1.add(a.c1, a.c0);
        this->c1.multiply(this->c1, o);
        this->c1.subtract(this->c1, aa);
        this->c1.subtract(this->c1, bb);
        this->c0.multiply_by_nonresidue(bb);
        this->c0.add(this->c0, aa);
    }

    void Fq12::square(const Fq12& a) {
        Fq6 ab;
        Fq6 c0c1;
        ab.multiply(a.c0, a.c1);
        c0c1.add(a.c0, a.c1);

        Fq6 tmp;
        tmp.multiply_by_nonresidue(a.c1);
        this->c0.add(a.c0, tmp);
        this->c0.multiply(this->c0, c0c1);
        this->c0.subtract(this->c0, ab);
        this->c1.multiply2(ab);
        ab.multiply_by_nonresidue(ab);
        this->c0.subtract(this->c0, ab);
    }

    void Fq12::multiply_by_c014(const Fq12& a, const Fq2& __restrict c0, const Fq2& __restrict c1, const Fq2& __restrict c4) {
        Fq6 aa;
        Fq6 bb;
        Fq2 o;
        aa.multiply_by_c01(a.c0, c0, c1);
        bb.multiply_by_c1(a.c1, c4);
        o.add(c1, c4);

        this->c1.add(a.c1, a.c0);
        this->c1.multiply_by_c01(this->c1, c0, o);
        this->c1.subtract(this->c1, aa);
        this->c1.subtract(this->c1, bb);

        this->c0.multiply_by_nonresidue(bb);
        this->c0.add(this->c0, aa);
    }

    void Fq12::conjugate(const Fq12& a) {
        this->c0.copy(a.c0);
        this->c1.negate(a.c1);
    }

    void Fq12::random(void (*get_random_bytes)(void*, size_t)) {
        this->c0.random(get_random_bytes);
        this->c1.random(get_random_bytes);
    }

    void Fq12::write_big_endian(uint8_t* buffer) const {
        this->c1.write_big_endian(&buffer[0]);
        this->c0.write_big_endian(&buffer[sizeof(Fq6)]);
    }

    void Fq12::read_big_endian(const uint8_t* buffer) {
        this->c0.read_big_endian(&buffer[sizeof(Fq6)]);
        this->c1.read_big_endian(&buffer[0]);
    }

    bool Fq12::equal(const Fq12& a, const Fq12& b) {
        bool c0_equal = Fq6::equal(a.c0, b.c0);
        bool c1_equal = Fq6::equal(a.c1, b.c1);
        return c0_equal && c1_equal;
    }
}
