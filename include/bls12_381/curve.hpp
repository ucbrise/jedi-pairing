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

#ifndef EMBEDDED_PAIRING_BLS12_381_CURVE_HPP_
#define EMBEDDED_PAIRING_BLS12_381_CURVE_HPP_

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "./fr.hpp"
#include "./fq.hpp"
#include "./fq2.hpp"

namespace embedded_pairing::bls12_381 {
    /*
     * The elliptic curves are of the form y^2 = x^3 + b.
     * For E(Fq), we use b = 4.
     * For E(Fq^2), we use b = 4(u + 1).
     */

    template <typename> struct Projective;

    template <typename BaseField, typename ScalarField, const BaseField& curve_b>
    struct Affine {
        /* Export template parameters. */
        typedef BaseField BaseFieldType;
        typedef ScalarField ScalarFieldType;
        static const constexpr BaseField& curve_b_value = curve_b;

        /* The elements of this struct. */
        BaseField x;
        BaseField y;
        bool infinity;

        /* Constant for zero. */
        static const Affine<BaseField, ScalarField, curve_b> zero;

        void set(const Projective<BaseField>& a) {
            this->from_projective(a);
        }

        void set(const Affine<BaseField, ScalarField, curve_b>& a) {
            this->copy(a);
        }

        void copy(const Affine<BaseField, ScalarField, curve_b>& a) {
            if (this != &a) {
                memcpy(this, &a, sizeof(*this));
            }
        }

        /*
         * Computes the affine coordinates of the elliptic curve point, given
         * only the x coordinate. If the provided x coordinate corresponds to a
         * point on the elliptic curve, the method returns true. If the
         * provided x coordinate does not correspond to a point on the curve,
         * and the "checked" template parameter is true, then the function will
         * detect it and return false. If the provided x coordinate does not
         * correspond to a point on the curve, and the "checked" template
         * parameter is false, then the function will not detect and _undefined
         * behavior_ will result.
         *
         * Note that y = sqrt(x^3 + b), so there are actually two possibilities
         * for y given a valid value of x. The GREATER argument determines
         * which point is chosen. If TRUE, the candidate with lexicographically
         * greater y coordinate is chosen; if false, the candidate with
         * lexicographically smaller y coordinate is chosen.
         *
         * Although the recovered point is guaranteed to be on the elliptic
         * curve, there is no guarantee that it will be in the appropriate
         * bilinear subgroup.
         */
        bool get_point_from_x(const BaseField& x, bool greater, bool checked = true) {
            /* Compute x^3 + b */
            BaseField x3b;
            x3b.square(x);
            x3b.multiply(x3b, x);
            x3b.add(x3b, curve_b);
            if (checked && x3b.legendre() == -1) {
                return false;
            }

            this->x.copy(x);
            this->y.square_root(x3b);

            BaseField negy;
            negy.negate(y);

            bool ywasgreater = (BaseField::compare(y, negy) == 1);
            if (greater != ywasgreater) {
                this->y.copy(negy);
            } else {
                negy.copy(this->y);
            }

            this->infinity = false;
            return true;
        }

        bool is_on_curve(void) const {
            BaseField y2;
            y2.square(this->y);

            BaseField x3b;
            x3b.square(this->x);
            x3b.multiply(x3b, x);
            x3b.add(x3b, curve_b);

            return BaseField::equal(y2, x3b);
        }

        bool is_in_correct_subgroup_assuming_on_curve(void) const {
            Projective<BaseField> ar;
            ar.multiply_restrict(*this, ScalarField::p_value);
            return ar.is_zero();
        }

        void try_and_increment(const BaseField& start, bool greater) {
            /* Taken from Sec. 1.1 of https://eprint.iacr.org/2009/226.pdf. */
            BaseField x;
            x.copy(start);

            while (!this->get_point_from_x(x, greater, true)) {
                x.add(x, BaseField::one);
            }
        }

        static bool equal(const Affine<BaseField, ScalarField, curve_b>& a, const Affine<BaseField, ScalarField, curve_b>& b) {
            bool x_equal = BaseField::equal(a.x, b.x);
            bool y_equal = BaseField::equal(a.y, b.y);
            return (a.infinity == b.infinity) && (a.infinity || (x_equal && y_equal));
        }

        bool is_zero(void) const {
            return this->infinity;
        }

        void negate(const Affine<BaseField, ScalarField, curve_b>& a) {
            this->x.copy(a.x);
            this->y.negate(a.y);
            this->infinity = a.infinity;
        }

        // TODO: Balance the if statement
        void from_projective(const Projective<BaseField>& __restrict a) {
            if (a.is_zero()) {
                this->copy(zero);
                return;
            }
#ifndef RESIST_SIDE_CHANNELS
            if (BaseField::equal(a.z, BaseField::one)) {
                this->x.copy(a.x);
                this->y.copy(a.y);
                this->infinity = false;
                return;
            }
#endif

            BaseField zinv;
            zinv.inverse(a.z);

            BaseField zinvpow;
            zinvpow.square(zinv);
            this->x.multiply(a.x, zinvpow);

            zinvpow.multiply(zinvpow, zinv);
            this->y.multiply(a.y, zinvpow);

            this->infinity = false;
        }
    };

    template <typename BaseField, typename ScalarField, const BaseField& curve_b>
    constexpr Affine<BaseField, ScalarField, curve_b> Affine<BaseField, ScalarField, curve_b>::zero = {
        .x = BaseField::zero,
        .y = BaseField::one,
        .infinity = true
    };

    template <typename BaseField>
    struct Projective {
        BaseField x;
        BaseField y;
        BaseField z;

        /* Export template parameter. */
        typedef BaseField BaseFieldType;

        static const Projective<BaseField> zero;

        void set(const Projective<BaseField>& a) {
            this->copy(a);
        }

        template <typename ScalarField, const BaseField& coeff_b>
        void set(const Affine<BaseField, ScalarField, coeff_b>& a) {
            this->from_affine(a);
        }

        void copy(const Projective<BaseField>& a) {
            if (this != &a) {
                memcpy(this, &a, sizeof(*this));
            }
        }

        static bool equal(const Projective<BaseField>& a, const Projective<BaseField>& b) {
            /* Point at infinity is represented by z = 0. */
            if (a.is_zero()) {
                return b.is_zero();
            }

            if (b.is_zero()) {
                return false;
            }

            /*
             * The affine coordinates (x, y) correspond to the projective
             * coordinates (xz^2, yz^3, z), for any nonzero z. We want to check
             * whether the affine coordinates, corresponding to the provided
             * projective coordinates, are equal.
             *
             * (X, Y, Z) and (X', Y', Z') are equal iff (X' * Z^2) = (X * Z'^2)
             * and (Y' * Z^3) = (Y * Z'^3).
             */

            BaseField z1;
            BaseField z2;
            z1.square(a.z);
            z2.square(b.z);

            BaseField tmp1;
            BaseField tmp2;
            tmp1.multiply(a.x, z2);
            tmp2.multiply(b.x, z1);

            z1.multiply(z1, a.z);
            z2.multiply(z2, b.z);
            z2.multiply(z2, a.y);
            z1.multiply(z1, b.y);

            return BaseField::equal(tmp1, tmp2) && BaseField::equal(z1, z2);
        }

        bool is_zero(void) const {
            return this->z.is_zero();
        }

        bool is_normalized(void) const {
            return this->is_zero() || BaseField::equal(this->z, BaseField::one);
        }

        void multiply2(const Projective<BaseField>& other) {
            if (other.is_zero()) {
                this->copy(other);
                return;
            }

            BaseField a;
            a.square(other.x);

            BaseField b;
            b.square(other.y);

            BaseField c;
            c.square(b);

            BaseField d;
            d.add(other.x, b);
            d.square(d);
            d.subtract(d, a);
            d.subtract(d, c);
            d.multiply2(d);

            BaseField e;
            e.multiply2(a);
            e.add(e, a);

            BaseField f;
            f.square(e);

            this->z.multiply(other.z, other.y);
            this->z.multiply2(this->z);

            this->x.subtract(f, d);
            this->x.subtract(this->x, d);

            this->y.subtract(d, this->x);
            this->y.multiply(this->y, e);
            c.multiply2(c);
            c.multiply2(c);
            c.multiply2(c);
            this->y.subtract(this->y, c);
        }

        void add(const Projective<BaseField>& a, const Projective<BaseField>& __restrict b) {
            if (b.is_zero()) {
                this->copy(a);
                return;
            }
            if (a.is_zero()) {
                this->copy(b);
                return;
            }

            // Z1Z1 = Z1^2
            BaseField z1z1;
            z1z1.square(a.z);

            // Z2Z2 = Z2^2
            BaseField z2z2;
            z2z2.square(b.z);

            // U1 = X1*Z2Z2
            BaseField u1;
            u1.multiply(a.x, z2z2);

            // U2 = X2*Z1Z1
            BaseField u2;
            u2.multiply(b.x, z1z1);

            // S1 = Y1*Z2*Z2Z2
            BaseField s1;
            s1.multiply(a.y, b.z);
            s1.multiply(s1, z2z2);

            // S2 = Y2*Z1*Z1Z1
            BaseField s2;
            s2.multiply(b.y, a.z);
            s2.multiply(s2, z1z1);

            /*
             * If u1 == u2 and s1 == s2, then the two points are equal. This
             * check is not simply an optimization, but is needed for
             * correctness. The later code fails in this case.
             */
            if (BaseField::equal(u1, u2) && BaseField::equal(s1, s2)) {
                this->multiply2(a);
                return;
            }

            // H = U2-U1
            BaseField h;
            h.subtract(u2, u1);

            // I = (2*H)^2
            BaseField i;
            i.multiply2(h);
            i.square(i);

            // J = H*I
            BaseField j;
            j.multiply(h, i);

            // r = 2*(S2-S1)
            BaseField r;
            r.subtract(s2, s1);
            r.multiply2(r);

            // V = U1*I
            BaseField v;
            v.multiply(u1, i);

            // X3 = r^2 - J - 2*V
            this->x.square(r);
            this->x.subtract(this->x, j);
            this->x.subtract(this->x, v);
            this->x.subtract(this->x, v);

            // Y3 = r*(V - X3) - 2*S1*J
            this->y.subtract(v, this->x);
            this->y.multiply(this->y, r);
            s1.multiply(s1, j);
            s1.multiply2(s1);
            this->y.subtract(this->y, s1);

            // Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*H
            this->z.add(a.z, b.z);
            this->z.square(this->z);
            this->z.subtract(this->z, z1z1);
            this->z.subtract(this->z, z2z2);
            this->z.multiply(this->z, h);
        }

        template <typename ScalarField, const BaseField& coeff_b>
        void add(const Projective<BaseField>& a, const Affine<BaseField, ScalarField, coeff_b>& __restrict b) {
            if (b.is_zero()) {
                this->copy(a);
                return;
            }
            if (a.is_zero()) {
                this->x.copy(b.x);
                this->y.copy(b.y);
                this->z.copy(BaseField::one);
                return;
            }

            BaseField z1z1;
            z1z1.square(a.z);

            BaseField u2;
            u2.multiply(b.x, z1z1);

            BaseField s2;
            s2.multiply(b.y, a.z);
            s2.multiply(s2, z1z1);

            /*
             * If a.x == u2 and a.y == s2, then the two points are equal. This
             * check is not simply an optimization, but is needed for
             * correctness. The later code fails in this case.
             */
            if (BaseField::equal(a.x, u2) && BaseField::equal(a.y, s2)) {
                this->multiply2(a);
                return;
            }

            BaseField h;
            h.subtract(u2, a.x);

            BaseField hh;
            hh.square(h);

            BaseField i;
            i.multiply2(hh);
            i.multiply2(i);

            BaseField j;
            j.multiply(h, i);

            BaseField r;
            r.subtract(s2, a.y);
            r.multiply2(r);

            BaseField v;
            v.multiply(a.x, i);

            this->x.square(r);
            this->x.subtract(this->x, j);
            this->x.subtract(this->x, v);
            this->x.subtract(this->x, v);

            j.multiply(j, a.y);
            j.multiply2(j);
            this->y.subtract(v, this->x);
            this->y.multiply(this->y, r);
            this->y.subtract(this->y, j);

            this->z.add(a.z, h);
            this->z.square(this->z);
            this->z.subtract(this->z, z1z1);
            this->z.subtract(this->z, hh);
        }

        void negate(const Projective<BaseField>& a) {
            this->x.copy(a.x);
            this->y.negate(a.y);
            this->z.copy(a.z);
        }

        /*
         * Scalar multiplication by repeated doubling. Almost equivalent to
         * the 'exponentiate' function in montgomeryfp_utils.hpp. We implement
         * this separately for two reasons:
         * 1) We need more flexibility with types for this implementation.
         * 2) We need slighly more general functionality, as inputs might come
         *    the user of this library, as opposed to within this library
         *    itself.
         */
        template <typename ArgType, typename BigInt>
        void multiply_restrict(const ArgType& __restrict base, const BigInt& __restrict scalar, int highest_bit = BigInt::bits_value - 1) {
#ifdef RESIST_SIDE_CHANNELS
            Projective<BaseField> tmp;
#endif
            this->copy(zero);
            for (int i = highest_bit; i != -1; i--) {
                this->multiply2(*this);
                if (scalar.bit(i)) {
                    this->add(*this, base);
                } else {
#ifdef RESIST_SIDE_CHANNELS
                    tmp.add(*this, base);
#endif
                }
            }
        }

        template <typename ArgType, typename BigInt>
        void multiply(const ArgType& base, const BigInt& __restrict scalar, int highest_bit = BigInt::bits_value - 1) {
            const ArgType tmp = base;
            this->multiply_restrict(tmp, scalar, highest_bit);
        }

        template <typename ScalarField, const BaseField& coeff_b>
        void from_affine(const Affine<BaseField, ScalarField, coeff_b>& __restrict a) {
            if (a.is_zero()) {
                this->copy(Projective<BaseField>::zero);
            } else {
                this->x.copy(a.x);
                this->y.copy(a.y);
                this->z.copy(BaseField::one);
            }
        }
    };

    template <typename BaseField>
    constexpr Projective<BaseField> Projective<BaseField>::zero = {
        .x = BaseField::zero,
        .y = BaseField::one,
        .z = BaseField::zero
    };

    static constexpr Fq g1_b_coeff = {
        {{{.std_words = { 0xcfff3, 0xaa270000, 0xfc34000a, 0x53cc0032, 0x6b0a807f, 0x478fe97a, 0xe6ba24d7, 0xb1d37ebe, 0xbf78ab2f, 0x8ec9733b, 0x3d83de7e, 0x9d64551 }}}}
    };
    static constexpr Fq2 g2_b_coeff = {
        .c0 = g1_b_coeff,
        .c1 = g1_b_coeff
    };

    extern const Fq g1_b_coeff_var;
    extern const Fq2 g2_b_coeff_var;

    struct G1Affine : Affine<Fq, Fr, g1_b_coeff_var> {
        static const G1Affine generator;
        static constexpr BigInt<128> cofactor = {
            .std_words = { 0xaaab, 0x8c00aaab, 0x5555e156, 0x396c8c00 }
        };

        static const G1Affine zero;
        static const G1Affine one;
    };
    constexpr G1Affine G1Affine::generator = {{
        .x = {{{{.std_words = { 0xfd530c16, 0x5cb38790, 0x9976fff5, 0x7817fc67, 0x143ba1c1, 0x154f95c7, 0xf3d0e747, 0xf0ae6acd, 0x21dbf440, 0xedce6ecc, 0x9e0bfb75, 0x12017741 }}}}},
        .y = {{{{.std_words = { 0xce72271, 0xbaac93d5, 0x7918fd8e, 0x8c22631a, 0x570725ce, 0xdd595f13, 0x50405194, 0x51ac5829, 0xad0059c0, 0xe1c8c3f, 0x5008a26a, 0xbbc3efc }}}}},
        .infinity = false
    }};
    constexpr G1Affine G1Affine::zero = {{
        .x = Fq::zero,
        .y = Fq::one,
        .infinity = true
    }};
    constexpr G1Affine G1Affine::one = G1Affine::generator;

    struct G1 : Projective<Fq> {
        static const G1 zero;
        static const G1 one;

        void random_generator(void (*get_random_bytes)(void*, size_t));
    };
    constexpr G1 G1::zero = {{
        .x = Fq::zero,
        .y = Fq::one,
        .z = Fq::zero
    }};
    constexpr G1 G1::one = {{
        .x = G1Affine::one.x,
        .y = G1Affine::one.y,
        .z = Fq::one
    }};

    struct G2Affine : Affine<Fq2, Fr, g2_b_coeff_var> {
        static const G2Affine generator;
        static constexpr BigInt<512> cofactor = {
            .std_words = { 0x1c7238e5, 0xcf1c38e3, 0x786f0c70, 0x1616ec6e, 0x3a6691ae, 0x21537e29, 0x4d9e82ef, 0xa628f1cb, 0x2e5a7ddf, 0xa68a205b, 0x47085aba, 0xcd91de45, 0x2876a202, 0x91d5079, 0x5414e7f1, 0x5d543a9 }
        };

        static const G2Affine zero;
        static const G2Affine one;
    };
    constexpr G2Affine G2Affine::generator = {{
        .x = {
            .c0 = {{{{.std_words = { 0x2940a10, 0xf5f28fa2, 0x87b4961a, 0xb3f5fb26, 0x3e2ae580, 0xa1a893b5, 0x1a3caee9, 0x9894999d, 0x1863366b, 0x6f67b763, 0x4350bcd7, 0x5819192 }}}}},
            .c1 = {{{{.std_words = { 0x9e23f606, 0xa5a9c075, 0xbccd60c3, 0xaaa0c59d, 0xe2867806, 0x3bb17e18, 0x8541b367, 0x1b1ab6cc, 0xf2158547, 0xc2b6ed0e, 0x7360edf3, 0x11922a09 }}}}}
        },
        .y = {
            .c0 = {{{{.std_words = { 0x60494c4a, 0x4c730af8, 0x5e369c5a, 0x597cfa1f, 0xaa0a635a, 0xe7e6856c, 0x6e0d495f, 0xbbefb5e9, 0xf0ef25a2, 0x7d3a975, 0x7e80dae5, 0x83fd8e }}}}},
            .c1 = {{{{.std_words = { 0xdf64b05d, 0xadc0fc92, 0x2b1461dc, 0x18aa270a, 0x3be4eba0, 0x86adac6a, 0xc93da33a, 0x79495c4e, 0xa43ccaed, 0xe7175850, 0x63de1bf2, 0xb2bc2a1 }}}}}
        },
        .infinity = false
    }};
    constexpr G2Affine G2Affine::zero = {{
        .x = Fq2::zero,
        .y = Fq2::one,
        .infinity = true
    }};
    constexpr G2Affine G2Affine::one = G2Affine::generator;

    struct G2 : Projective<Fq2> {
        static const G2 zero;
        static const G2 one;

        void random_generator(void (*get_random_bytes)(void*, size_t));
    };
    constexpr G2 G2::zero = {{
        .x = Fq2::zero,
        .y = Fq2::one,
        .z = Fq2::zero
    }};;
    constexpr G2 G2::one = {{
        .x = G2Affine::one.x,
        .y = G2Affine::one.y,
        .z = Fq2::one
    }};

    /* Encoding in raw bytes. */

    template <typename Affine, bool compressed>
    struct Encoding {
        static constexpr size_t size = compressed ? sizeof(typename Affine::BaseFieldType) : 2 * sizeof(typename Affine::BaseFieldType);
        uint8_t data[size];

        void encode(const Affine& g);
        bool decode(Affine& g, bool checked) const;
    };

    constexpr uint8_t encoding_flags_compressed = 1 << 7;
    constexpr uint8_t encoding_flags_infinity = 1 << 6;
    constexpr uint8_t encoding_flags_greater = 1 << 5;
    inline bool is_encoding_compressed(uint8_t first_byte) {
        return (first_byte & encoding_flags_compressed) != 0;
    }

    /* Encoding struct is explicitly instantiated in curve.cpp. */
    typedef Encoding<G1Affine, false> G1Uncompressed;
    typedef Encoding<G1Affine, true> G1Compressed;
    typedef Encoding<G2Affine, false> G2Uncompressed;
    typedef Encoding<G2Affine, true> G2Compressed;
}

#endif
