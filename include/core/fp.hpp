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

#ifndef EMBEDDED_PAIRING_CORE_FP_HPP_
#define EMBEDDED_PAIRING_CORE_FP_HPP_

#include "./bigint.hpp"
#include "./fp_utils.hpp"

namespace embedded_pairing::core {
    /*
     * Normally you would use the struct Fp, which inherits from this
     * struct, rather than using this one directly. This base class contains
     * the parts of Fp that lend themselves to architecture-specific
     * optimizations.
     */
    template <int bits>
    struct FpBase {
        /*
         * Export template parameters so it is accessible in function
         * templates that just get an opaque type.
         */
        static constexpr int bits_value = bits;

        /* The only element of this struct. */
        BigInt<bits> val;

        void add(const FpBase<bits>& a, const FpBase<bits>& __restrict b, const BigInt<bits>& __restrict p) {
#ifdef RESIST_SIDE_CHANNELS
            BigInt<bits> tmp;
#endif
            bool carry = this->val.add(a.val, b.val);
            if (BigInt<bits>::compare(this->val, p) >= 0 || carry) {
                this->val.subtract(this->val, p);
            } else {
#ifdef RESIST_SIDE_CHANNELS
                tmp.subtract(this->val, p);
#endif
            }
        }

        void multiply2(const FpBase<bits>& a, const BigInt<bits>& __restrict p) {
#ifdef RESIST_SIDE_CHANNELS
            BigInt<bits> tmp;
#endif
            typename BigInt<bits>::word_t shift_out;
            shift_out = this->val.template shift_left_in_word<1>(a.val);
            if (BigInt<bits>::compare(this->val, p) >= 0 || shift_out != 0) {
                this->val.subtract(this->val, p);
            } else {
#ifdef RESIST_SIDE_CHANNELS
                tmp.subtract(this->val, p);
#endif
            }
        }

        void subtract(const FpBase<bits>& a, const FpBase<bits>& __restrict b, const BigInt<bits>& __restrict p) {
#ifdef RESIST_SIDE_CHANNELS
            BigInt<bits> tmp;
#endif
            bool borrow = this->val.subtract(a.val, b.val);
            if (borrow) {
                this->val.add(this->val, p);
            } else {
#ifdef RESIST_SIDE_CHANNELS
                tmp.add(this->val, p);
#endif
            }
        }

        void negate(const FpBase<bits>& a, const BigInt<bits>& __restrict p) {
            if (a.val.is_zero()) {
#ifdef RESIST_SIDE_CHANNELS
                this->val.subtract(a.val, BigInt<bits>::zero);
#else
                this->val.copy(a.val);
#endif
            } else {
                this->val.subtract(p, a.val);
            }
        }

        void reduce(const BigInt<bits>& __restrict a, const BigInt<bits>& __restrict p) {
            if (BigInt<bits>::compare(a, p) == -1) {
#ifdef RESIST_SIDE_CHANNELS
                this->val.subtract(a, BigInt<bits>::zero);
#else
                this->val.copy(a);
#endif
            } else {
                this->val.subtract(a, p);
            }
        }

        void montgomery_reduce(BigInt<2*bits>& __restrict a, const BigInt<bits>& __restrict p, typename BigInt<bits>::word_t inv_word) {
            /* Montgomery reduction with b = word size, n = num words. */

            typename BigInt<bits>::word_t meta_carry = 0;
            for (int i = 0; i != BigInt<bits>::word_length; i++) {
                typename BigInt<bits>::word_t u = a.words[i] * inv_word;
                typename BigInt<bits>::word_t carry;

                {
                    /* Handle j == 0 case separately, since it is simpler. */
                    typename BigInt<bits>::dword_t new_word = ((typename BigInt<bits>::dword_t) u) * ((typename BigInt<bits>::dword_t) p.words[0]) + a.words[i];
                    carry = new_word >> (sizeof(typename BigInt<bits>::word_t) * 8);
                    /*
                     * We can skip the store a.words[i] = (word_t) new_word,
                     * since we anyway discard the bottom half of the product.
                     */
                }

                for (int j = 1; j != BigInt<bits>::word_length; j++) {
                    typename BigInt<bits>::dword_t new_word = ((typename BigInt<bits>::dword_t) u) * ((typename BigInt<bits>::dword_t) p.words[j]) + a.words[i + j] + carry;
                    carry = new_word >> (sizeof(typename BigInt<bits>::word_t) * 8);
                    a.words[i + j] = (typename BigInt<bits>::word_t) new_word;
                }

                /*
                 * Unlike the case of normal multiply, this addition could
                 * actually overflow, as there's data already here. Therefore
                 * we need the meta_carry to handle this.
                 */
                typename BigInt<bits>::dword_t new_sum = ((typename BigInt<bits>::dword_t) a.words[i + BigInt<bits>::word_length]) + ((typename BigInt<bits>::dword_t) carry) + ((typename BigInt<bits>::dword_t) meta_carry);
                meta_carry = new_sum >> (sizeof(typename BigInt<bits>::word_t) * 8);
                a.words[i + BigInt<bits>::word_length] = (typename BigInt<bits>::word_t) new_sum;
            }

            this->reduce(*reinterpret_cast<BigInt<bits>*>(&a.bytes[bits/8]), p);
        }

        void multiply(const FpBase<bits>& a, const FpBase<bits>& b, const BigInt<bits>& __restrict p, typename BigInt<bits>::word_t inv_word) {
            BigInt<2*bits> tmp;
            tmp.multiply(a.val, b.val);
            this->montgomery_reduce(tmp, p, inv_word);
        }

        void square(const FpBase<bits>& a, const BigInt<bits>& __restrict p, typename BigInt<bits>::word_t inv_word) {
            BigInt<2*bits> tmp;
            tmp.square(a.val);
            this->montgomery_reduce(tmp, p, inv_word);
        }
    };

    /*
     * The struct Fp<bits, p, r, r2, mpinv> is a POD representing
     * an integer in Fp in Montgomery form. An integer x in [0, p-1] is
     * represented as x * r mod p, for some conveniently chosen r that
     * makes reduction modulo p efficient after multiplication.
     *
     * p is the prime modulus. r is the montgomery constant, which should
     * be chosen as (2 ** bits) % p. r2 is the square of the montgomery
     * constant, used to convert numbers into montgomery form; it is
     * (r ** 2) % p. inv is (-(p^{-1} mod (2 ** bits)) mod (2 ** bits)),
     * used for montgomery reduction with n = 1.
     */
    template <int bits, const BigInt<bits>& p, const BigInt<bits>& r, const BigInt<bits>& r2, const BigInt<bits>& inv>
    struct Fp : FpBase<bits> {
        /*
         * Export template parameters so they are accessible in function
         * templates that just get an opaque type.
         */
        static constexpr int bits_value = bits;
        static const constexpr BigInt<bits>& p_value = p;
        static const constexpr BigInt<bits>& r_value = r;
        static const constexpr BigInt<bits>& r2_value = r2;
        static const constexpr BigInt<bits>& inv_value = inv;

        /* Constants for zero and one. */
        static const Fp<bits, p, r, r2, inv> zero;
        static const Fp<bits, p, r, r2, inv> one;

        void set_zero(void) {
            memset(this, 0x00, sizeof(*this));
        }

        bool is_zero(void) const {
            return this->val.is_zero();
        }

        void copy(const FpBase<bits>& a) {
            this->val.copy(a.val);
        }

        void copy(const BigInt<bits>& a) {
            this->val.copy(a);
        }

        static bool equal(const FpBase<bits>& a, const FpBase<bits>& b) {
            return BigInt<bits>::equal(a.val, b.val);
        }

        bool is_one(void) const {
            return BigInt<bits>::equal(this->val, r);
        }

        void set(const BigInt<bits>& integer) {
            const FpBase<bits>* a = reinterpret_cast<const FpBase<bits>*>(&integer);
            const FpBase<bits>* b = reinterpret_cast<const FpBase<bits>*>(&r2);
            this->FpBase<bits>::multiply(*a, *b, p, inv.words[0]);
        }

        /*
         * If you manually copy something into this->val, you need to call this
         * function before multiplication will work properly. If you do not
         * manually write to this->val, then it should not be necessary to call
         * this method.
         */
        void into_montgomery_form(void) {
            const FpBase<bits>* b = reinterpret_cast<const FpBase<bits>*>(&r2);
            this->FpBase<bits>::multiply(*this, *b, p, inv.words[0]);
        }

        void get(BigInt<bits>& integer) const {
            BigInt<2*bits> tmp;
            tmp.copy(this->val);

            Fp<bits, p, r, r2, inv>* target;
            target = reinterpret_cast<Fp<bits, p, r, r2, inv>*>(&integer);
            target->montgomery_reduce(tmp);
        }

        void add(const Fp<bits, p, r, r2, inv>& a, const Fp<bits, p, r, r2, inv>& __restrict b) {
            this->FpBase<bits>::add(a, b, p);
        }

        void multiply2(const Fp<bits, p, r, r2, inv>& a) {
            this->FpBase<bits>::multiply2(a, p);
        }

        void subtract(const Fp<bits, p, r, r2, inv>& a, const Fp<bits, p, r, r2, inv>& __restrict b) {
            this->FpBase<bits>::subtract(a, b, p);
        }

        void negate(const Fp<bits, p, r, r2, inv>& a) {
            this->FpBase<bits>::negate(a, p);
        }

        void reduce(const BigInt<bits>& __restrict a) {
            this->FpBase<bits>::reduce(a, p);
        }

        /*
         * It's an open question whether montgomery_reduce and multiply should
         * really be methods, or if they need to go in fp_utils.hpp.
         * On the one hand, they belong here since they operate on BigInts
         * directly. On the other hand, they call internal functions, which may
         * be assembly-optimized in a subclass. My guess is that an
         * implementation that optimizes one of these in assembly is likely
         * to also optimize the others, so I'm leaving it as-is for now.
         */

        // void montgomery_reduce(BigInt<2*bits>& __restrict value) {
        //     /* Montgomery reduction with b = 2^384, n = 1 */
        //     BigInt<bits> tmp1;
        //     BigInt<2*bits> tmp2;
        //     const BigInt<bits>* lower_value = reinterpret_cast<const BigInt<bits>*>(&value);
        //     tmp1.multiply_lower(*lower_value, inv);
        //     tmp2.multiply(tmp1, p);
        //     tmp2.add(tmp2, value);
        //     this->reduce(*reinterpret_cast<BigInt<bits>*>(&tmp2.bytes[bits/8]));
        // }

        void montgomery_reduce(BigInt<2*bits>& __restrict a) {
            this->FpBase<bits>::montgomery_reduce(a, p, inv.words[0]);
        }

        void __attribute__((noinline)) multiply(const Fp<bits, p, r, r2, inv>& a, const Fp<bits, p, r, r2, inv>& b) {
            this->FpBase<bits>::multiply(a, b, p, inv.words[0]);
        }

        void __attribute__((noinline)) square(const Fp<bits, p, r, r2, inv>& a) {
            this->FpBase<bits>::square(a, p, inv.words[0]);
        }

        int legendre(void) const {
            /*
             * This value of (p - 1) // 2 could be precomputed, but it's
             * unlikely anyone would actually want to compute the legendre
             * symbol at runtime anyway.
             *
             * If we cared about optimizing performance, we may want to
             * consider putting this in fp_utils.hpp as a function
             * template, to make sure that we instantiate the exponentiate
             * function template according to the appropriate subclass of this
             * template, as the subclass may have optimized methods.
             */
            BigInt<bits> pminusoneovertwo;
            pminusoneovertwo.subtract(p, BigInt<bits>::one);
            pminusoneovertwo.template shift_right_in_word<1>(pminusoneovertwo);

            Fp<bits, p, r, r2, inv> tmp;
            exponentiate(tmp, *this, pminusoneovertwo);

            if (tmp.is_zero()) {
                return 0;
            } else if (tmp.is_one()) {
                return 1;
            } else {
                return -1;
            }
        }
    };

    template <int bits, const BigInt<bits>& p, const BigInt<bits>& r, const BigInt<bits>& r2, const BigInt<bits>& inv>
    constexpr Fp<bits, p, r, r2, inv> Fp<bits, p, r, r2, inv>::zero = {{ .val = BigInt<bits>::zero }};

    /* TODO: Figure out how to make this definition constexpr. */
    template <int bits, const BigInt<bits>& p, const BigInt<bits>& r, const BigInt<bits>& r2, const BigInt<bits>& inv>
    const Fp<bits, p, r, r2, inv> Fp<bits, p, r, r2, inv>::one = {{ .val = r }};
}

#ifndef DISABLE_ASM

/*
 * Figure out the architecture of the current platform, and import the
 * appropriate headers for optimization.
 */

#if defined(__ARM_ARCH_6M__)
#include "./arch/armv6_m/fp.hpp"
#endif

#if defined(__x86_64__) || defined(_M_X64_)
#include "./arch/x86_64/fp.hpp"
#endif

#endif /* NO_ASM */

#endif
