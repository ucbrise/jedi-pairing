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

#ifndef EMBEDDED_PAIRING_BLS12_381_FQ2_HPP_
#define EMBEDDED_PAIRING_BLS12_381_FQ2_HPP_

#include <stddef.h>

#include "./fq.hpp"

namespace embedded_pairing::bls12_381 {
    struct Fq2 {
        Fq c0;
        Fq c1;

        static const Fq2 one;
        static const Fq2 zero;
        static const Fq2 negative_one;

        bool is_zero(void) const;
        void copy(const Fq2& a);
        void add(const Fq2& a, const Fq2& __restrict b);
        void multiply2(const Fq2& a);
        void subtract(const Fq2& a, const Fq2& __restrict b);
        void negate(const Fq2& a);
        void inverse(const Fq2& a);
        void frobenius_map(const Fq2& a, unsigned int power);
        void multiply(const Fq2& a, const Fq2& b);
        void square(const Fq2& a);
        void multiply_by_nonresidue(const Fq2& a);
        void norm(Fq& __restrict result) const;
        int legendre(void) const;
        void square_root(const Fq2& __restrict a);
        void random(void (*get_random_bytes)(void*, size_t));
        void write_big_endian(uint8_t* buffer) const;
        void read_big_endian(const uint8_t* buffer);

        static bool equal(const Fq2& a, const Fq2& b);
        static int compare(const Fq2& a, const Fq2& b);
    };

    constexpr Fq2 Fq2::one = {.c0 = Fq::one, .c1 = Fq::zero};
    constexpr Fq2 Fq2::zero = {.c0 = Fq::zero, .c1 = Fq::zero};
    constexpr Fq2 Fq2::negative_one = {.c0 = Fq::negative_one, .c1 = Fq::zero};
}

#endif
