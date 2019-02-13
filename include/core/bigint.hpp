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

#ifndef EMBEDDED_PAIRING_CORE_BIGINT_HPP_
#define EMBEDDED_PAIRING_CORE_BIGINT_HPP_

#include <stdint.h>
#include <string.h>

namespace embedded_pairing::core {
    /*
     * The union BigInt<bits> is a POD representing a big integer of
     * specified width in bits. The width in bits MUST be a multiple of the
     * largest integer supported by the compiler, or the size of the second
     * largest integer supported by the compiler
     */
    template <int bits>
    union BigInt {
        /*
         * Export template parameter so it is accessible in function templates
         * that just get an opaque type.
         */
        static const int bits_value = bits;

        /*
         * Figure out which types to use for the bigint implementation.
         * We want to use the largest supported type (since the compiler's
         * implementation is likely better than what we can do in C++) but
         * fall back to other implementations in case some integer sizes
         * are not supported.
         */
#if defined(__SIZEOF_INT128__)
        typedef unsigned __int128 dword_t;
        typedef uint64_t word_t;
#elif defined(UINT64_MAX)
        typedef uint64_t dword_t;
        typedef uint32_t word_t;
#else
#error "Support for uint64_t is required, but not present."
#endif

        /* Length of this BigInt in various units. */
        static constexpr int byte_length = 1 + ((bits - 1) / 8);
        static constexpr int word_length = 1 + ((byte_length - 1) / sizeof(word_t));
        static constexpr int dword_length = 1 + ((byte_length - 1) / sizeof(dword_t));
        static constexpr int std_word_length = 1 + ((byte_length - 1) / sizeof(uint32_t));

        /* The elements of this union. */
        dword_t dwords[dword_length];
        word_t words[word_length];
        uint8_t bytes[byte_length];
        uint32_t std_words[std_word_length];

        /* Constants for zero and one. */
        static const BigInt<bits> zero;
        static const BigInt<bits> one;

        void clear(void) {
            memset(this, 0x00, sizeof(BigInt<bits>));
        }

        bool is_zero(void) const {
#ifdef RESIST_SIDE_CHANNELS
            word_t res = this->words[0];
            for (int i = 1; i != word_length; i++) {
                res |= this->words[i];
            }
            return res == 0;
#else
            for (int i = 0; i != word_length; i++) {
                if (this->words[i] != 0) {
                    return false;
                }
            }
            return true;
#endif
        }

        bool is_one(void) const {
#ifdef RESIST_SIDE_CHANNELS
            dword_t res = (this->words[0] - 1) | this->words[1];
            for (int i = 1; i != dword_length; i++) {
                res |= this->dwords[i];
            }
            return res == 0;
#else
            if (this->dwords[0] != 1) {
                return false;
            }
            for (int i = 1; i != dword_length; i++) {
                if (this->dwords[i] != 0) {
                    return false;
                }
            }
            return true;
#endif
        }

        bool is_even(void) const {
            return (this->bytes[0] & 0x1) == 0x0;
        }

        bool is_odd(void) const {
            return (this->bytes[0] & 0x1) == 0x1;
        }

        bool bit(int position) const {
            uint8_t byte = this->bytes[position >> 3];
            return (byte & (((uint8_t) 1) << (position & 0x7))) != 0;
        }

        template <int from_bits>
        void copy(const BigInt<from_bits>& a) {
            if constexpr(bits <= from_bits) {
                memmove(&this->bytes[0], &a.bytes[0], sizeof(this->bytes));
            } else {
                memmove(&this->bytes[0], &a.bytes[0], sizeof(a.bytes));
                memset(&this->bytes[sizeof(a.bytes)], 0x0, sizeof(this->bytes) - sizeof(a.bytes));
            }
        }

        static bool equal(const BigInt<bits>& a, const BigInt<bits>& b) {
#ifdef RESIST_SIDE_CHANNELS
            dword_t res = a.words[0] ^ b.words[0];
            for (int i = 1; i != dword_length; i++) {
                res |= (a.words[i] ^ b.words[i]);
            }
            return res == 0;
#else
            return memcmp(a.bytes, b.bytes, BigInt<bits>::byte_length) == 0;
#endif
        }

        static int compare(const BigInt<bits>& a, const BigInt<bits>& b) {
#ifdef RESIST_SIDE_CHANNELS
            int result = 0;
            for (int i = 0; i != word_length; i++) {
                if (a.words[i] < b.words[i]) {
                    result = -1;
                }
                if (a.words[i] > b.words[i]) {
                    result = 1;
                }
            }
            return result;
#else
            for (int i = word_length - 1; i != -1; i--) {
                if (a.words[i] < b.words[i]) {
                    return -1;
                }
                if (a.words[i] > b.words[i]) {
                    return 1;
                }
            }
            return 0;
#endif
        }

        bool add(const BigInt<bits>& a, const BigInt<bits>& __restrict b) {
            if constexpr(bits < dword_length * 8) {
                uint8_t carry = 0;
                for (int i = 0; i != word_length; i++) {
                    this->words[i] = a.words[i] + b.words[i] + carry;
                    if (carry == 0) {
                        carry = (this->words[i] < b.words[i]) ? 1 : 0;
                    } else {
                        carry = (this->words[i] <= b.words[i]) ? 1 : 0;
                    }
                }
                return (carry != 0);
            } else {
                uint8_t carry = 0;
                for (int i = 0; i != dword_length; i++) {
                    this->dwords[i] = a.dwords[i] + b.dwords[i] + carry;
                    if (carry == 0) {
                        carry = (this->dwords[i] < b.dwords[i]) ? 1 : 0;
                    } else {
                        carry = (this->dwords[i] <= b.dwords[i]) ? 1 : 0;
                    }
                }
                return (carry != 0);
            }
        }

        bool subtract(const BigInt<bits>& a, const BigInt<bits>& __restrict b) {
            if constexpr(bits < dword_length * 8) {
                uint8_t borrow = 0;
                for (int i = 0; i != word_length; i++) {
                    dword_t old_a_val = a.words[i];
                    this->words[i] = a.words[i] - b.words[i] - borrow;
                    if (borrow == 0) {
                        borrow = (old_a_val < this->words[i]) ? 1 : 0;
                    } else {
                        borrow = (old_a_val <= this->words[i]) ? 1 : 0;
                    }
                }
                return (borrow != 0);
            } else {
                uint8_t borrow = 0;
                for (int i = 0; i != dword_length; i++) {
                    dword_t old_a_val = a.dwords[i];
                    this->dwords[i] = a.dwords[i] - b.dwords[i] - borrow;
                    if (borrow == 0) {
                        borrow = (old_a_val < this->dwords[i]) ? 1 : 0;
                    } else {
                        borrow = (old_a_val <= this->dwords[i]) ? 1 : 0;
                    }
                }
                return (borrow != 0);
            }
        }

        template <uint8_t amt>
        word_t shift_right_in_word(const BigInt<bits>& a) {
            word_t shift_in = 0;
            for (int i = word_length - 1; i != -1; i--) {
                word_t new_shift_in = a.words[i] << ((sizeof(word_t) * 8) - amt);
                this->words[i] = shift_in | (a.words[i] >> amt);
                shift_in = new_shift_in;
            }
            return shift_in;
        }

        template <uint8_t amt>
        word_t shift_left_in_word(const BigInt<bits>& a) {
            word_t shift_in = 0;
            for (int i = 0; i != word_length; i++) {
                word_t new_shift_in = a.words[i] >> ((sizeof(word_t) * 8) - amt);
                this->words[i] = (a.words[i] << amt) | shift_in;
                shift_in = new_shift_in;
            }
            return shift_in;
            // word_t rv = (this->words[word_length - 1] >> ((sizeof(word_t) * 8) - amt));
            // for (int i = dword_length - 1; i != 0; i--) {
            //     this->dwords[i] = (this->dwords[i] << amt) | (dword_t) (this->words[(i << 1) - 1] >> ((sizeof(word_t) * 8) - amt));
            // }
            // this->dwords[0] <<= amt;
            // return rv;
        }

        word_t shift_right(const BigInt<bits>& a, unsigned int amt) {
            unsigned int word_offset = amt / (sizeof(word_t) * 8);
            unsigned int bit_offset = amt % (sizeof(word_t) * 8);
            word_t shift_in = 0;
            for (int i = word_length - word_offset - 1; i != -1; i--) {
                /*
                 * It turns out that the code:
                 * word_t new_shift_in = a.words[i+word_offset]
                 *     << ((sizeof(word_t) *8) - bit_offset);
                 * is actually WRONG. If bit_offset == 0, it may, e.g.,
                 * take a uint64_t and shift it left by 64 bits, which is
                 * undefined behavior. On my computer this actually is the
                 * same a shifting left by 0 (i.e., leaves the original
                 * word unchanged).
                 * The solution is to shift in two stages, to handle this
                 * edge case.
                 */
                word_t new_shift_in = a.words[i + word_offset] << ((sizeof(word_t) * 8) - bit_offset - 1);
                new_shift_in <<= 1;
                this->words[i] = shift_in | (a.words[i + word_offset] >> bit_offset);
                shift_in = new_shift_in;
            }

            /* We wait until the end, in case this and a are aliased. */
            for (int i = 0; i != word_offset; i++) {
                this->words[word_length - i - 1] = 0;
            }

            return shift_in;
        }

        word_t shift_left(const BigInt<bits>& a, unsigned int amt) {
            unsigned int word_offset = amt / (sizeof(word_t) * 8);
            unsigned int bit_offset = amt % (sizeof(word_t) * 8);
            word_t shift_in = 0;
            for (int i = word_offset; i != word_length; i++) {
                /* See comment above in shift_right. */
                word_t new_shift_in = a.words[i - word_offset] >> ((sizeof(word_t) * 8) - bit_offset - 1);
                new_shift_in >>= 1;
                this->words[i] = (a.words[i - word_offset] << bit_offset) | shift_in;
                shift_in = new_shift_in;
            }

            /* We wait until the end, in case this and a are aliased. */
            for (int i = 0; i != word_offset; i++) {
                this->words[i] = 0;
            }

            return shift_in;
        }

        // void multiply(const BigInt<bits/2>& __restrict a, const BigInt<bits/2>& __restrict b) {
        //     memset(this->bytes, 0x0, sizeof(this->bytes) / 2);
        //     for (int i = 0; i != a.word_length; i++) {
        //         word_t carry = 0;
        //         int j;
        //         for (j = 0; j != b.word_length; j++) {
        //             dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) b.words[j]) + this->words[i + j] + carry;
        //             carry = new_word >> (sizeof(word_t) * 8);
        //             this->words[i + j] = (word_t) new_word;
        //         }
        //         this->words[i + j] = carry;
        //     }
        // }

        template <int a_bits>
        void multiply(const BigInt<a_bits>& __restrict a, const BigInt<bits - a_bits>& __restrict b) {
            {
                /* First iteration of loop; avoids memset at the beginning. */
                word_t carry = 0;
                for (int j = 0; j != b.word_length; j++) {
                    dword_t new_word = ((dword_t) a.words[0]) * ((dword_t) b.words[j]) + carry;
                    carry = new_word >> (sizeof(word_t) * 8);
                    this->words[j] = (word_t) new_word;
                }
                this->words[b.word_length] = carry;
            }

            for (int i = 1; i != a.word_length; i++) {
                word_t carry = 0;
                for (int j = 0; j != b.word_length; j++) {
                    dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) b.words[j]) + this->words[i + j] + carry;
                    carry = new_word >> (sizeof(word_t) * 8);
                    this->words[i + j] = (word_t) new_word;
                }
                this->words[i + b.word_length] = carry;
            }
        }

        template <word_t divisor>
        word_t divide_word(const BigInt<bits>& a) {
            word_t rem = 0;
            for (int i = a.word_length - 1; i != -1; i--) {
                dword_t dividend = (((dword_t) rem) << (sizeof(word_t) * 8)) | ((dword_t) a.words[i]);
                word_t quotient;
                if (dividend == 0) {
                    quotient = 0;
                } else {
                    quotient = dividend / divisor;
                    rem = dividend % divisor;
                }
                this->words[i] = quotient;
            }
            return rem;
        }

        // void square(const BigInt<bits/2>& __restrict a) {
        //     this->multiply(a, a);
        // }

        void square(const BigInt<bits/2>& __restrict a) {
            /*
             * In the multiply case, we can imagine a grid, where the cell at
             * index (i, j) contains the product of the ith word of a with the
             * jth word of b. The product is a "fancy" sum over all of these
             * partial products, in which cell (i, j) is added at position
             * i + j, contributing carry to position i + j + 1.
             *
             * In the case of squaring a number, this grid is symmetric across
             * its diagonal, with perfect squares along the diagonal. We can,
             * therefore, optimize squaring by first computing one half of the
             * grid (e.g., everything below the diagonal), shifting it to the
             * left by one to account for the other half, and then adding the
             * perfect squares along the diagonal.
             */

            /* Handle half of the grid. */
            this->dwords[0] = 0;
            for (int i = 1; i != a.word_length; i++) {
                word_t carry = 0;
                int j;
                for (j = 0; j != i; j++) {
                    dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) a.words[j]) + this->words[i + j] + carry;
                    carry = new_word >> (sizeof(word_t) * 8);
                    this->words[i + j] = (word_t) new_word;
                }
                this->dwords[i] = (dword_t) carry;
            }

            /*
             * Double the result. We know that the highest word is empty, so we
             * can do this more efficiently than the regular shift method.
             */
             this->words[word_length - 1] = this->words[word_length - 2] >> ((sizeof(word_t) * 8) - 1);
             this->words[word_length - 2] = (this->words[word_length - 2] << 1) | (this->words[word_length - 3] >> ((sizeof(word_t) * 8) - 1));
             for (int i = dword_length - 2; i != 0; i--) {
                 this->dwords[i] = (this->dwords[i] << 1) | (this->dwords[i - 1] >> ((sizeof(dword_t) * 8) - 1));
             }
             this->dwords[0] <<= 1;

            /* Handle the diagonal. */
            word_t carry = 0;
            for (int i = 0; i != a.word_length; i++) {
                //dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) a.words[i]) + this->dwords[i] + carry;

                /*
                 * This carry check works because we know that
                 * ((dword_t) a.words[i]) * ((dword_t) a.words[i]) + carry
                 * will not overflow.
                 */
                // carry = (new_word < this->dwords[i]) ? 1 : 0;
                // this->dwords[i] = new_word;

                dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) a.words[i]) + this->words[i << 1] + carry;
                this->words[i << 1] = (word_t) new_word;
                carry = (word_t) (new_word >> (sizeof(word_t) * 8));
                new_word = ((dword_t) this->words[(i << 1) + 1]) + ((dword_t) carry);
                this->words[(i << 1) + 1] = (word_t) new_word;
                carry = (word_t) (new_word >> (sizeof(word_t) * 8));
            }
        }

        void multiply_lower(const BigInt<bits>& __restrict a, const BigInt<bits>& __restrict b) {
            this->clear();
            for (int i = 0; i != word_length; i++) {
                word_t carry = 0;
                int j;
                for (j = 0; j != word_length - i; j++) {
                    dword_t new_word = ((dword_t) a.words[i]) * ((dword_t) b.words[j]) + this->words[i + j] + carry;
                    carry = new_word >> (sizeof(word_t) * 8);
                    this->words[i + j] = (word_t) new_word;
                }
            }
        }

        /*
         * These "big endian" functions can be optimized, but I'm leaving it as
         * a TODO for now.
         */

        void reverse_endianness(void) {
            for (int i = 0; i != byte_length / 2; i++) {
                uint8_t first = this->bytes[i];
                uint8_t last = this->bytes[byte_length - i - 1];
                this->bytes[i] = last;
                this->bytes[byte_length - i - 1] = first;
            }
        }

        void write_big_endian(uint8_t* buffer) const {
            for (int i = 0; i != byte_length; i++) {
                buffer[i] = this->bytes[byte_length - i - 1];
            }
        }

        void read_big_endian(const uint8_t* buffer) {
            for (int i = 0; i != byte_length; i++) {
                this->bytes[i] = buffer[byte_length - i - 1];
            }
        }

        void random(void (*get_random_bytes)(void*, size_t)) {
            get_random_bytes(this->bytes, byte_length);
        }
    };

    template <int bits>
    constexpr BigInt<bits> BigInt<bits>::zero = {.std_words = {0}};

    template <int bits>
    constexpr BigInt<bits> BigInt<bits>::one = {.std_words = {1}};
}

#ifndef DISABLE_ASM

/*
 * Figure out the architecture of the current platform, and import the
 * appropriate headers for optimization.
 */

#if defined(__ARM_ARCH_6M__)
#include "./arch/armv6_m/bigint.hpp"
#endif

#if defined(__x86_64__) || defined(_M_X64_)
#include "./arch/x86_64/bigint.hpp"
#endif

#if defined(__aarch64__)
#include "./arch/aarch64/bigint.hpp"
#endif

#endif /* NO_ASM */

#endif
