/*
 * Copyright (c) 2019, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2019, University of California, Berkeley
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

#ifndef EMBEDDED_PAIRING_CORE_ARCH_AARCH64_FP_HPP_
#define EMBEDDED_PAIRING_CORE_ARCH_AARCH64_FP_HPP_

#include "core/fp.hpp"

extern "C" {
    void embedded_pairing_core_arch_aarch64_fpbase_384_multiply(void* res, const void* a, const void* b, const void* p, uint64_t inv_word);
    void embedded_pairing_core_arch_aarch64_fpbase_384_square(void* res, const void* a, const void* p, uint64_t inv_word);
    void embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);
}

namespace embedded_pairing::core {
    template <>
    inline void FpBase<384>::multiply(const FpBase<384>& a, const FpBase<384>& b, const BigInt<384>& __restrict p, typename BigInt<384>::word_t inv_word) {
        BigInt<384> tmp;
        embedded_pairing_core_arch_aarch64_fpbase_384_multiply(&tmp, &a, &b, &p, inv_word);
        this->reduce(*reinterpret_cast<BigInt<384>*>(&tmp), p);
    }

    template <>
    inline void FpBase<384>::square(const FpBase<384>& a, const BigInt<384>& __restrict p, typename BigInt<384>::word_t inv_word) {
        BigInt<384> tmp;
        embedded_pairing_core_arch_aarch64_fpbase_384_square(&tmp, &a, &p, inv_word);
        this->reduce(*reinterpret_cast<BigInt<384>*>(&tmp), p);
    }

    template <>
    inline void FpBase<384>::montgomery_reduce(BigInt<768>& __restrict a, const BigInt<384>& __restrict p, typename BigInt<384>::word_t inv_word) {
        BigInt<384> tmp;
        embedded_pairing_core_arch_aarch64_fpbase_384_montgomery_reduce(&tmp, &a, &p, inv_word);
        this->reduce(*reinterpret_cast<BigInt<384>*>(&tmp), p);
    }
}

#endif
