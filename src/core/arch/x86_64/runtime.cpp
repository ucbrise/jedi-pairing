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

#include <stdint.h>

extern "C" {
    bool embedded_pairing_core_arch_x86_64_cpu_supports_bmi2_adx(void);

    void embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);
    void embedded_pairing_core_arch_x86_64_bmi2_adx_montgomeryfpbase_384_montgomery_reduce(void* res, void* a, const void* p, uint64_t inv_word);

    void embedded_pairing_core_arch_x86_64_bigint_768_multiply(void* res, const void* a, const void* b);
    void embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_multiply(void* res, const void* a, const void* b);

    void embedded_pairing_core_arch_x86_64_bigint_768_square(void* res, const void* a);
    void embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_square(void* res, const void* a);
}

namespace embedded_pairing::core {
    static bool cpu_supports_bmi2_adx = embedded_pairing_core_arch_x86_64_cpu_supports_bmi2_adx();
    void (*runtime_montgomeryfpbase_384_montgomery_reduce)(void*, void*, const void*, uint64_t) = cpu_supports_bmi2_adx ? embedded_pairing_core_arch_x86_64_bmi2_adx_montgomeryfpbase_384_montgomery_reduce : embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce;
    void (*runtime_bigint_768_multiply)(void*, const void*, const void*) = cpu_supports_bmi2_adx ? embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_multiply : embedded_pairing_core_arch_x86_64_bigint_768_multiply;
    void (*runtime_bigint_768_square)(void*, const void*) = cpu_supports_bmi2_adx ? embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_square : embedded_pairing_core_arch_x86_64_bigint_768_square;
 }
