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

// In the macros below, the carry status flag is implicitly part of carry_in
// and carry_out; if the it is one, the actual value is one more than what is
// indicated in the actual register.

.macro multiply64 dst, carry_out, arg0, arg1
    umulh \carry_out, \arg0, \arg1
    mul \dst, \arg0, \arg1
.endm

.macro mulcarry64 dst, carry_out, arg0, arg1, carry_in
    mul \dst, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adcs \dst, \dst, \carry_in
.endm

.macro muladd64 dst, carry_out, arg0, arg1, scratch
    mul \scratch, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adds \dst, \dst, \scratch
.endm

.macro muladdcarry64 dst, carry_out, arg0, arg1, carry_in, scratch
    mul \scratch, \arg0, \arg1
    umulh \carry_out, \arg0, \arg1
    adcs \dst, \dst, \scratch
    adcs \carry_out, \carry_out, xzr
    adds \dst, \dst, \carry_in
.endm

.macro multiply768firstiteration res0, res1, res2, res3, res4, res5, res6, ar0, br0, br1, br2, br3, br4, br5, carry
    adds xzr, xzr, xzr // Clear carry flag
    multiply64 \res0, \carry, \ar0, \br0
    mulcarry64 \res1, \res6, \ar0, \br1, \carry
    mulcarry64 \res2, \carry, \ar0, \br2, \res6
    mulcarry64 \res3, \res6, \ar0, \br3, \carry
    mulcarry64 \res4, \carry, \ar0, \br4, \res6
    mulcarry64 \res5, \res6, \ar0, \br5, \carry
    adcs \res6, \res6, xzr
.endm

.macro multiply768iteration res0, res1, res2, res3, res4, res5, res6, ar0, br0, br1, br2, br3, br4, br5, carry, scratch
    muladd64 \res0, \carry, \ar0, \br0, \scratch
    muladdcarry64 \res1, \res6, \ar0, \br1, \carry, \scratch
    muladdcarry64 \res2, \carry, \ar0, \br2, \res6, \scratch
    muladdcarry64 \res3, \res6, \ar0, \br3, \carry, \scratch
    muladdcarry64 \res4, \carry, \ar0, \br4, \res6, \scratch
    muladdcarry64 \res5, \res6, \ar0, \br5, \carry, \scratch
    adcs \res6, \res6, xzr
.endm

// Sets res := a * b
// Does not preserve a[0] and a[1], but preserves b and the rest of a
.macro multiply768 res0, res1, res2, res3, res4, res5, res6, res7, res8, res9, res10, res11, ar0, ar1, ar2, ar3, ar4, ar5, br0, br1, br2, br3, br4, br5
    multiply768firstiteration \res0, \res1, \res2, \res3, \res4, \res5, \res6, \ar0, \br0, \br1, \br2, \br3, \br4, \br5, \res11
    multiply768iteration \res1, \res2, \res3, \res4, \res5, \res6, \res7, \ar1, \br0, \br1, \br2, \br3, \br4, \br5, \res11, \ar0
    multiply768iteration \res2, \res3, \res4, \res5, \res6, \res7, \res8, \ar2, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res3, \res4, \res5, \res6, \res7, \res8, \res9, \ar3, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res4, \res5, \res6, \res7, \res8, \res9, \res10, \ar4, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
    multiply768iteration \res5, \res6, \res7, \res8, \res9, \res10, \res11, \ar5, \br0, \br1, \br2, \br3, \br4, \br5, \ar1, \ar0
.endm

.global embedded_pairing_core_arch_aarch64_bigint_768_multiply
.type embedded_pairing_core_arch_aarch64_bigint_768_multiply, %function
.text

embedded_pairing_core_arch_aarch64_bigint_768_multiply:
    // Save registers
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!

    // Load b into {x9, x10, x11, x12, x13, x14}
    ldp x9, x10, [x2], #16
    ldp x11, x12, [x2], #16
    ldp x13, x14, [x2], #16

    // Load a into {x2, x3, x4, x5, x6, x7}
    ldp x2, x3, [x1], #16
    ldp x4, x5, [x1], #16
    ldp x6, x7, [x1], #16

    multiply768 x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x2, x3, x4, x5, x6, x7, x9, x10, x11, x12, x13, x14

    // Store result from {x1, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28}
    stp x1, x15, [x0], #16
    stp x19, x20, [x0], #16
    stp x21, x22, [x0], #16
    stp x23, x24, [x0], #16
    stp x25, x26, [x0], #16
    stp x27, x28, [x0], #16

    // Restore registers and return
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ret
