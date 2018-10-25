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

#include "bls12_381/fq.hpp"
#include "bls12_381/fq2.hpp"

namespace embedded_pairing::bls12_381 {
    static constexpr Fq fq2_frobenius_coeff[2] = {
        {{{{.std_words = {0x2fffd, 0x76090000, 0xc40c0002, 0xebf4000b, 0x53c758ba, 0x5f489857, 0x70525745, 0x77ce5853, 0xa256ec6d, 0x5c071a97, 0xfa80e493, 0x15f65ec3}}}}},
        {{{{.std_words = {0xfffcaaae, 0x43f5ffff, 0xed47fffd, 0x32b7fff2, 0xa2e99d69, 0x7e83a49, 0x8332bb7a, 0xeca8f331, 0xa0f4c069, 0xef148d1e, 0x3eff0206, 0x40ab326}}}}}
    };
    /* The constant (q - 3) // 4, used for computing the square root. */
    static constexpr BigInt<fq_bits> fq2_qminusthreeoverfour = {
        .std_words = {0xffffeaaa, 0xee7fbfff, 0xac54ffff, 0x7aaffff, 0x3dac3d89, 0xd9cc34a8, 0x3ce144af, 0xd91dd2e1, 0x90d2eb35, 0x92c6e9ed, 0x8e5ff9a6, 0x680447a}
    };
    /* The constant (q - 1) // 2, used for computing the square root. */
    static constexpr BigInt<fq_bits> fq2_qminusoneovertwo = {
        .std_words = {0xffffd555, 0xdcff7fff, 0x58a9ffff, 0xf55ffff, 0x7b587b12, 0xb3986950, 0x79c2895f, 0xb23ba5c2, 0x21a5d66b, 0x258dd3db, 0x1cbff34d, 0xd0088f5}
    };

    bool Fq2::is_zero(void) const {
        bool c0_zero = this->c0.is_zero();
        bool c1_zero = this->c1.is_zero();
        return c0_zero && c1_zero;
    }

    void Fq2::copy(const Fq2& a) {
        this->c0.copy(a.c0);
        this->c1.copy(a.c1);
    }

    void Fq2::add(const Fq2& a, const Fq2& __restrict b) {
        this->c0.add(a.c0, b.c0);
        this->c1.add(a.c1, b.c1);
    }

    void Fq2::multiply2(const Fq2& a) {
        this->c0.multiply2(a.c0);
        this->c1.multiply2(a.c1);
    }

    void Fq2::subtract(const Fq2& a, const Fq2& __restrict b) {
        this->c0.subtract(a.c0, b.c0);
        this->c1.subtract(a.c1, b.c1);
    }

    void Fq2::negate(const Fq2& a) {
        this->c0.negate(a.c0);
        this->c1.negate(a.c1);
    }

    void Fq2::inverse(const Fq2& a) {
        Fq t0;
        Fq t1;
        t0.square(a.c0);
        t1.square(a.c1);
        t0.add(t0, t1);

        montgomeryfp_inverse(t1, t0);
        this->c0.multiply(a.c0, t1);
        this->c1.multiply(a.c1, t1);
        this->c1.negate(this->c1);
    }

    void Fq2::frobenius_map(const Fq2& a, unsigned int power) {
        this->c0.copy(a.c0);
        this->c1.multiply(a.c1, fq2_frobenius_coeff[power & 0x1]);
    }

    void Fq2::multiply(const Fq2& a, const Fq2& b) {
        Fq aa;
        Fq bb;
        Fq o;
        aa.multiply(a.c0, b.c0);
        bb.multiply(a.c1, b.c1);
        o.add(b.c0, b.c1);

        this->c1.add(a.c1, a.c0);
        this->c1.multiply(this->c1, o);
        this->c1.subtract(this->c1, aa);
        this->c1.subtract(this->c1, bb);
        this->c0.subtract(aa, bb);
    }

    void Fq2::square(const Fq2& a) {
        Fq ab;
        Fq c0c1;
        ab.multiply(a.c0, a.c1);
        c0c1.add(a.c0, a.c1);

        this->c0.subtract(a.c0, a.c1);
        this->c0.multiply(this->c0, c0c1);
        this->c1.multiply2(ab);
    }

    void Fq2::multiply_by_nonresidue(const Fq2& a) {
        Fq t0;
        t0.copy(a.c0);
        this->c0.subtract(a.c0, a.c1);
        this->c1.add(a.c1, t0);
    }

    void Fq2::norm(Fq& __restrict result) const {
        Fq t;
        result.square(this->c0);
        t.square(this->c1);
        result.add(result, t);
    }

    int Fq2::legendre(void) const {
        Fq norm_value;
        this->norm(norm_value);
        return norm_value.legendre();
    }

    // TODO balance the if statement
    void Fq2::square_root(const Fq2& __restrict a) {
        if (a.is_zero()) {
            this->copy(a);
            return;
        }
        exponentiate(*this, a, fq2_qminusthreeoverfour);
        Fq2 alpha;
        alpha.square(*this);
        alpha.multiply(alpha, a);

        this->multiply(*this, a);
        if (Fq2::equal(alpha, Fq2::negative_one)) {
            Fq2 constant = {.c0 = Fq::zero, .c1 = Fq::one};
            this->multiply(*this, constant);
        } else {
            alpha.add(alpha, Fq2::one);

            Fq2 alphapow;
            exponentiate(alphapow, alpha, fq2_qminusoneovertwo);
            this->multiply(*this, alphapow);
        }
    }

    void Fq2::random(void (*get_random_bytes)(void*, size_t)) {
        this->c0.random(get_random_bytes);
        this->c1.random(get_random_bytes);
    }

    void Fq2::write_big_endian(uint8_t* buffer) const {
        this->c1.write_big_endian(&buffer[0]);
        this->c0.write_big_endian(&buffer[sizeof(Fq)]);
    }

    void Fq2::read_big_endian(const uint8_t* buffer) {
        this->c0.read_big_endian(&buffer[sizeof(Fq)]);
        this->c1.read_big_endian(&buffer[0]);
    }

    bool Fq2::equal(const Fq2& a, const Fq2& b) {
        bool c0_equal = Fq::equal(a.c0, b.c0);
        bool c1_equal = Fq::equal(a.c1, b.c1);
        return c0_equal && c1_equal;
    }

    int Fq2::compare(const Fq2& a, const Fq2& b) {
        int c1_cmp = Fq::compare(a.c1, b.c1);
        int c0_cmp = Fq::compare(a.c0, b.c0);

        return (c1_cmp == 0) ? c0_cmp : c1_cmp;
    }
}
