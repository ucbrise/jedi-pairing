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

#ifndef EMBEDDED_PAIRING_CORE_ARCH_X86_64_MONTGOMERYFP_HPP_
#define EMBEDDED_PAIRING_CORE_ARCH_X86_64_MONTGOMERYFP_HPP_

extern "C" {
    void embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);
    void embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);
}

namespace embedded_pairing::core {
    template <>
    inline void MontgomeryFpBase<384>::montgomery_reduce(BigInt<768>& __restrict a, const BigInt<384>& __restrict p, typename BigInt<384>::word_t inv_word) {
#ifdef __BMI2__
        embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce(this, &a, &p, inv_word);
#else
        embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce(this, &a, &p, inv_word);
#endif
    }
}

#endif
