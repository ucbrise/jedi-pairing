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

#ifndef EMBEDDED_PAIRING_BLS12_381_FQ6_HPP_
#define EMBEDDED_PAIRING_BLS12_381_FQ6_HPP_

#include <stddef.h>

#include "./fq2.hpp"

namespace embedded_pairing::bls12_381 {
    struct Fq6 {
        Fq2 c0;
        Fq2 c1;
        Fq2 c2;

        static const Fq6 one;
        static const Fq6 zero;

        bool is_zero(void) const;
        void copy(const Fq6& a);
        void add(const Fq6& a, const Fq6& __restrict b);
        void multiply2(const Fq6& a);
        void subtract(const Fq6& a, const Fq6& __restrict b);
        void negate(const Fq6& a);
        void inverse(const Fq6& a);
        void frobenius_map(const Fq6& a, unsigned int power);
        void multiply(const Fq6& a, const Fq6& b);
        void square(const Fq6& a);
        void multiply_by_nonresidue(const Fq6& a);
        void multiply_by_c1(const Fq6& a, const Fq2& __restrict c1);
        void multiply_by_c01(const Fq6& a, const Fq2& __restrict c0, const Fq2& __restrict c1);
        void random(void (*get_random_bytes)(void*, size_t));
        void write_big_endian(uint8_t* buffer) const;
        void read_big_endian(const uint8_t* buffer);

        static bool equal(const Fq6& a, const Fq6& b);
    };

    constexpr Fq6 Fq6::one = {.c0 = Fq2::one, .c1 = Fq2::zero, .c2 = Fq2::zero};
    constexpr Fq6 Fq6::zero = {.c0 = Fq2::zero, .c1 = Fq2::zero, .c2 = Fq2::zero};
}

#endif
