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

#ifndef EMBEDDED_PAIRING_CORE_CORE_H_
#define EMBEDDED_PAIRING_CORE_CORE_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 embedded_pairing_core_bigint_dword_t;
typedef uint64_t embedded_pairing_core_bigint_word_t;
#elif defined(UINT64_MAX)
typedef uint64_t embedded_pairing_core_bigint_dword_t;
typedef uint32_t embedded_pairing_core_bigint_word_t;
#elif defined(UINT32_MAX)
typedef uint32_t embedded_pairing_core_bigint_dword_t;
typedef uint16_t embedded_pairing_core_bigint_word_t;
#else
#error "Support for uint32_t is required, but not present."
#endif

typedef struct {
    embedded_pairing_core_bigint_dword_t dwords[256 / (8 * sizeof(embedded_pairing_core_bigint_dword_t))];
} embedded_pairing_core_bigint_256_t;

typedef struct {
    embedded_pairing_core_bigint_dword_t dwords[384 / (8 * sizeof(embedded_pairing_core_bigint_dword_t))];
} embedded_pairing_core_bigint_384_t;

#ifdef __cplusplus
}
#endif

#endif
