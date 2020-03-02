/*
 * Copyright (c) 2020, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2020, University of California, Berkeley
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

#ifndef EMBEDDED_PAIRING_BLS12_381_DECOMPOSITION_HPP_
#define EMBEDDED_PAIRING_BLS12_381_DECOMPOSITION_HPP_

#include "core/bigint.hpp"

namespace embedded_pairing::bls12_381 {
    struct PowersOfX {
        BigInt<64> c[4];

        /*
         * Decomposes an integer y (mod r) as (c0, c1, c2, c3) such that each
         * c is in [0, |x|) and y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3.
         */
        void decompose(const BigInt<256>& __restrict y);

        /*
         * Chooses random c0, c1, c2, c3 such that each c is in [0, |x|) and
         * y = c0 + c1*|x| + c2*|x|^2 + c3*|x|^3 is uniformly distributed in
         * [0, r).
         */
        void random(BigInt<256>& __restrict y, void (*get_random_bytes)(void*, size_t));
    };
}

#endif
