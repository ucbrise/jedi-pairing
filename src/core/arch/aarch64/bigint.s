// Copyright (c) 2019, Sam Kumar <samkumar@cs.berkeley.edu>
// Copyright (c) 2019, University of California, Berkeley
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its
//    contributors may be used to endorse or promote products derived from
//    this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// AArch64 calling convention: x0 - x7 are used for call arguments and results,
// x9 - x15 are temporary registers (caller-saved), and x19 - x28 (and sp) must
// be saved/restored if modified (callee-saved). Additionally, x8, x16, and x17
// are reserved for the linker (long branches), x29 is the frame pointer, and
// x30 is the link register (return address). x18 is a "platform register" that
// should not be used in portable code.

.global embedded_pairing_core_arch_aarch64_bigint_384_add
.type embedded_pairing_core_arch_aarch64_bigint_384_add, %function
.text

embedded_pairing_core_arch_aarch64_bigint_384_add:
    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    adds x3, x3, x5
    adcs x4, x4, x6
    stp x3, x4, [x0], #16

    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    adcs x3, x3, x5
    adcs x4, x4, x6
    stp x3, x4, [x0], #16

    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    adcs x3, x3, x5
    adcs x4, x4, x6
    stp x3, x4, [x0], #16

    cset x0, cs
    ret

.global embedded_pairing_core_arch_aarch64_bigint_384_subtract
.type embedded_pairing_core_arch_aarch64_bigint_384_subtract, %function
.text

embedded_pairing_core_arch_aarch64_bigint_384_subtract:
    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    subs x3, x3, x5
    sbcs x4, x4, x6
    stp x3, x4, [x0], #16

    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    sbcs x3, x3, x5
    sbcs x4, x4, x6
    stp x3, x4, [x0], #16

    ldp x3, x4, [x1], #16
    ldp x5, x6, [x2], #16
    sbcs x3, x3, x5
    sbcs x4, x4, x6
    stp x3, x4, [x0], #16

    cset x0, cc
    ret

.global embedded_pairing_core_arch_aarch64_bigint_384_multiply2
.type embedded_pairing_core_arch_aarch64_bigint_384_multiply2, %function
.text

embedded_pairing_core_arch_aarch64_bigint_384_multiply2:
    ldp x2, x3, [x1], #16
    adds x2, x2, x2
    adcs x3, x3, x3
    stp x2, x3, [x0], #16

    ldp x2, x3, [x1], #16
    adcs x2, x2, x2
    adcs x3, x3, x3
    stp x2, x3, [x0], #16

    ldp x2, x3, [x1], #16
    adcs x2, x2, x2
    adcs x3, x3, x3
    stp x2, x3, [x0], #16

    cset x0, cs
    ret

.global embedded_pairing_core_arch_aarch64_fpbase_384_add
.type embedded_pairing_core_arch_aarch64_fpbase_384_add, %function
.text

embedded_pairing_core_arch_aarch64_fpbase_384_add:
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x2], #16
    adds x4, x4, x6
    adcs x5, x5, x7

    ldp x6, x7, [x1], #16
    ldp x9, x10, [x2], #16
    adcs x6, x6, x9
    adcs x7, x7, x10

    ldp x9, x10, [x1], #16
    ldp x11, x12, [x2], #16
    adcs x9, x9, x11
    adcs x10, x10, x12

    // Now, x4, x5, x6, x7, x9, and x10 store the sum

    ldp x15, x1, [x3, #32]

    // As a heuristic
    b.cs embedded_pairing_core_arch_aarch64_fpbase_384_add_final_subtract
    cmp x1, x10
    b.hi embedded_pairing_core_arch_aarch64_fpbase_384_add_copy_original

embedded_pairing_core_arch_aarch64_fpbase_384_add_final_subtract:
    // Now x11, x12, x13, x14, x15, and x1 store p
    ldp x11, x12, [x3], #16
    subs x11, x4, x11
    sbcs x12, x5, x12

    ldp x13, x14, [x3], #16
    sbcs x13, x6, x13
    sbcs x14, x7, x14

    sbcs x15, x9, x15
    sbcs x1, x10, x1

    // Now x11, x12, x13, x14, x15, and x1 store (sum - p)

    b.cs embedded_pairing_core_arch_aarch64_fpbase_384_add_copy_subtracted

embedded_pairing_core_arch_aarch64_fpbase_384_add_copy_original:
    stp x4, x5, [x0], #16
    stp x6, x7, [x0], #16
    stp x9, x10, [x0], #16
    ret

embedded_pairing_core_arch_aarch64_fpbase_384_add_copy_subtracted:
    stp x11, x12, [x0], #16
    stp x13, x14, [x0], #16
    stp x15, x1, [x0], #16
    ret
