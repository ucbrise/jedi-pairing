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

#ifndef EMBEDDED_PAIRING_CORE_ARCH_THUMB_BIGINT_HPP_
#define EMBEDDED_PAIRING_CORE_ARCH_THUMB_BIGINT_HPP_

#include "core/bigint.hpp"

extern "C" {
    bool embedded_pairing_core_arch_thumb_bigint_384_add(void* res, const void* a, const void* b);
    void embedded_pairing_core_arch_thumb_bigint_768_multiply(void* res, const void* a, const void* b);
    void embedded_pairing_core_arch_thumb_bigint_768_multiply_alt(void* res, const void* a, const void* b);
    void embedded_pairing_core_arch_thumb_bigint_768_square_alt(void* res, const void* a);
}

namespace embedded_pairing::core {
    template <>
    inline bool BigInt<384>::add(const BigInt<384>& a, const BigInt<384>& __restrict b) {
        return embedded_pairing_core_arch_thumb_bigint_384_add(this, &a, &b);
    }

    template <>
    inline void BigInt<768>::multiply(const BigInt<384>& __restrict a, const BigInt<384>& __restrict b) {
        embedded_pairing_core_arch_thumb_bigint_768_multiply_alt(&this->words, &a.words, &b.words);
    }

    template <>
    inline void BigInt<768>::square(const BigInt<384>& __restrict a) {
        embedded_pairing_core_arch_thumb_bigint_768_square_alt(&this->words, &a.words);
    }
}

#endif
