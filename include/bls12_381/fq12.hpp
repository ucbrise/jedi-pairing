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

        static bool equal(const Fq12& a, const Fq12& b);
    };

    constexpr Fq12 Fq12::one = {.c0 = Fq6::one, .c1 = Fq6::zero};
    constexpr Fq12 Fq12::zero = {.c0 = Fq6::zero, .c1 = Fq6::zero};
}

#endif
