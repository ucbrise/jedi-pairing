# Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
# Copyright (c) 2018, University of California, Berkeley
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# x86_64 calling convention (assuming System V ABI): rdi, rsi, rdx, rcx, r8,
# and r9 are the argument registers, and rax is the return value (also rdx for
# larger 128-bit return values). The registers rbx, rbp, and r12-r15 must be
# saved and restored by a function if it modifies them.

.globl embedded_pairing_core_arch_x86_64_bigint_768_multiply
.type embedded_pairing_core_arch_x86_64_bigint_768_multiply, @function
.text

# Input carry and output carry are in rdx.
.macro mulcarry64 src1, src2, dst, scratch
    movq %rdx, \scratch
    movq \src1, %rax
    mulq \src2
    add \scratch, %rax
    adc $0, %rdx
    movq %rax, \dst
.endm

.macro muladd64 src1, src2, dst
    movq \src1, %rax
    mulq \src2
    add %rax, \dst
    adc $0, %rdx
.endm

.macro muladdcarry64 src1, src2, dst, scratch
    movq %rdx, \scratch
    movq \src1, %rax
    mulq \src2
    add \scratch, %rax
    adc $0, %rdx
    add %rax, \dst
    adc $0, %rdx
.endm

.macro multiplyloopiteration i, dst0, dst1, dst2, dst3, dst4, dst5
    movq (8*\i)(%rsi), %r9
    muladd64 %r9, (%rcx), \dst0
    movq \dst0, (8*\i)(%rdi)
    muladdcarry64 %r9, 8(%rcx), \dst1, \dst0
    muladdcarry64 %r9, 16(%rcx), \dst2, \dst0
    muladdcarry64 %r9, 24(%rcx), \dst3, \dst0
    muladdcarry64 %r9, 32(%rcx), \dst4, \dst0
    muladdcarry64 %r9, 40(%rcx), \dst5, \dst0
.endm

embedded_pairing_core_arch_x86_64_bigint_768_multiply:
    push %r12
    push %r13
    push %r14
    push %r15

    # mul writes result to rdx and rax, so we cannot use rdx as a pointer to
    # the multiplicand. Instead, we use rcx for this purpose. Similarly, we
    # cannot keep the carry in %rdx in-between multiplies, as it needs to be
    # added. So, we use r8 for the carry.
    movq %rdx, %rcx

    # r9 is used to cache the value in the first operand for the duration of
    # each loop.
    movq (%rsi), %r9

    # r10 - r15 are used to store parts of the destination BigInt.

    movq %r9, %rax
    mulq (%rcx)
    movq %rax, (%rdi)

    mulcarry64 %r9, 8(%rcx), %r10, %r8
    mulcarry64 %r9, 16(%rcx), %r11, %r8
    mulcarry64 %r9, 24(%rcx), %r12, %r8
    mulcarry64 %r9, 32(%rcx), %r13, %r8
    mulcarry64 %r9, 40(%rcx), %r14, %r8
    movq %rdx, %r15

    multiplyloopiteration 1, %r10, %r11, %r12, %r13, %r14, %r15
    movq %rdx, %r10
    multiplyloopiteration 2, %r11, %r12, %r13, %r14, %r15, %r10
    movq %rdx, %r11
    multiplyloopiteration 3, %r12, %r13, %r14, %r15, %r10, %r11
    movq %rdx, %r12
    multiplyloopiteration 4, %r13, %r14, %r15, %r10, %r11, %r12
    movq %rdx, %r13
    multiplyloopiteration 5, %r14, %r15, %r10, %r11, %r12, %r13

    movq %r15, 48(%rdi)
    movq %r10, 56(%rdi)
    movq %r11, 64(%rdi)
    movq %r12, 72(%rdi)
    movq %r13, 80(%rdi)
    movq %rdx, 88(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    ret

.globl embedded_pairing_core_arch_x86_64_bigint_768_square
.type embedded_pairing_core_arch_x86_64_bigint_768_square, @function
.text

.macro adddiagonal tosquare, addlo, addhi
    movq \tosquare, %rax
    mulq %rax
    add %r8, %rax
    adc $0, %rdx
    add %rax, \addlo
    adc %rdx, \addhi
    movq $0, %r8
    adc $0, %r8

.endm

# rdi is a pointer to the destination BigInt<768>. rsi is a pointer to the
# operand (which is a BigInt<384>).
embedded_pairing_core_arch_x86_64_bigint_768_square:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Iteration i = 1 (word 8(%rdi) in r10, word 16(%rdi) in r11)
    movq 8(%rsi), %rax
    mulq (%rsi)
    movq %rax, %r10
    movq %rdx, %r11

    # Iteration i = 2 (word 24(%rdi) in r12, word 32(%rdi) in r13)
    movq 16(%rsi), %r9
    muladd64 %r9, (%rsi), %r11
    mulcarry64 %r9, 8(%rsi), %r12, %r8
    movq %rdx, %r13

    # Iteration i = 3 (word 40(%rdi) in r14, word 48(%rdi) in r15)
    movq 24(%rsi), %r9
    muladd64 %r9, (%rsi), %r12
    muladdcarry64 %r9, 8(%rsi), %r13, %r8
    mulcarry64 %r9, 16(%rsi), %r14, %r8
    movq %rdx, %r15

    # Iteration i = 4 (word 56(%rdi) in rcx, word 64(%rdi) in rbp)
    movq 32(%rsi), %r9
    muladd64 %r9 (%rsi), %r13
    muladdcarry64 %r9 8(%rsi), %r14, %r8
    muladdcarry64 %r9 16(%rsi), %r15, %r8
    mulcarry64 %r9, 24(%rsi), %rcx, %r8
    movq %rdx, %rbp

    # Iteration i = 5 (word 72(%rdi) in rbx, word 80(%rdi) in r9)
    movq 40(%rsi), %r9
    muladd64 %r9, (%rsi), %r14
    muladdcarry64 %r9, 8(%rsi), %r15, %r8
    muladdcarry64 %r9, 16(%rsi), %rcx, %r8
    muladdcarry64 %r9, 24(%rsi), %rbp, %r8
    mulcarry64 %r9, 32(%rsi), %rbx, %r8
    movq %rdx, %r9

    # Double result
    add %r10, %r10
    adc %r11, %r11
    adc %r12, %r12
    adc %r13, %r13
    adc %r14, %r14
    adc %r15, %r15
    adc %rcx, %rcx
    adc %rbp, %rbp
    adc %rbx, %rbx
    adc %r9, %r9

    # Add diagonal (r8 stores the carry)
    movq (%rsi), %rax
    mulq %rax
    movq %rax, (%rdi)
    add %rdx, %r10
    movq %r10, 8(%rdi)
    movq $0, %r8
    adc $0, %r8

    adddiagonal 8(%rsi), %r11, %r12
    movq %r11, 16(%rdi)
    movq %r12, 24(%rdi)

    adddiagonal 16(%rsi), %r13, %r14
    movq %r13, 32(%rdi)
    movq %r14, 40(%rdi)

    adddiagonal 24(%rsi), %r15, %rcx
    movq %r15, 48(%rdi)
    movq %rcx, 56(%rdi)

    adddiagonal 32(%rsi), %rbp, %rbx
    movq %rbp, 64(%rdi)
    movq %rbx, 72(%rdi)

    movq 40(%rsi), %rax
    mulq %rax
    add %r8, %rax
    adc $0, %rdx
    add %rax, %r9
    movq %r9, 80(%rdi)
    adc $0, %rdx
    movq %rdx, 88(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret

.globl embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce
.type embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce, @function
.text

# The constant u used in multiplications for this iteration should be in r9.
# dst0 to dst5 should contain words i to i + 5 of product (total 12 words)
# At the end, dst1 - dst5 contain words i + 1 to i + 5 of the product
# rdx is the carry that should be added to word (i+6)
.macro montgomeryreduceloopiterationraw i, dst0, dst1, dst2, dst3, dst4, dst5
    muladd64 %r9, (%r8), \dst0
    # \dst0 is now free, so we use it for carry
    muladdcarry64 %r9, 8(%r8), \dst1, \dst0
    muladdcarry64 %r9, 16(%r8), \dst2, \dst0
    muladdcarry64 %r9, 24(%r8), \dst3, \dst0
    muladdcarry64 %r9, 32(%r8), \dst4, \dst0
    muladdcarry64 %r9, 40(%r8), \dst5, \dst0
.endm

# At the end, dst1 - dst5, dst0 contain words i + 1 to i + 6 of the product
# Carry bit is the "+1" bit for word i + 6 (in dst0).
.macro montgomeryreduceloopiteration i, dst0, dst1, dst2, dst3, dst4, dst5
    # Compute u and store it in %r9
    movq %rcx, %r9
    imul \dst0, %r9

    montgomeryreduceloopiterationraw \i, \dst0, \dst1, \dst2, \dst3, \dst4, \dst5

    # Use/store meta-carry in %rbx
    add %rbx, %rdx
    movq $0, %rbx
    adc %rbx, %rbx
    movq (8*\i+48)(%rsi), \dst0
    add %rdx, \dst0
    adc $0, %rbx
.endm

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Stash the prime modulus in r8, since rdx is used for multiplication
    movq %rdx, %r8

    # rbx is used for meta-carry
    xor %rbx, %rbx

    # Registers r10 to r15 store parts of the product (pointer in rsi)
    movq (%rsi), %r10
    movq 8(%rsi), %r11
    movq 16(%rsi), %r12
    movq 24(%rsi), %r13
    movq 32(%rsi), %r14
    movq 40(%rsi), %r15

    # First iteration
    movq %rcx, %r9
    imul %r10, %r9
    montgomeryreduceloopiterationraw 0, %r10, %r11, %r12, %r13, %r14, %r15
    movq 48(%rsi), %r10
    add %rdx, %r10
    adc %rbx, %rbx

    # Middle iterations
    montgomeryreduceloopiteration 1, %r11, %r12, %r13, %r14, %r15, %r10
    montgomeryreduceloopiteration 2, %r12, %r13, %r14, %r15, %r10, %r11
    montgomeryreduceloopiteration 3, %r13, %r14, %r15, %r10, %r11, %r12
    montgomeryreduceloopiteration 4, %r14, %r15, %r10, %r11, %r12, %r13

    # Final iteration
    movq %rcx, %r9
    imul %r15, %r9
    montgomeryreduceloopiterationraw 5, %r15, %r10, %r11, %r12, %r13, %r14
    add %rbx, %rdx
    add 88(%rsi), %rdx
    movq %rdx, %r15

    # Compare, and branch to either copy or subtraction
    cmp 40(%r8), %r15
    jb embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_copy
    je embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_subtract

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_subtract_compare:
    sub (%r8), %r10
    movq %r10, (%rdi)
    sbb 8(%r8), %r11
    movq %r11, 8(%rdi)
    sbb 16(%r8), %r12
    movq %r12, 16(%rdi)
    sbb 24(%r8), %r13
    movq %r13, 24(%rdi)
    sbb 32(%r8), %r14
    movq %r14, 32(%rdi)
    sbb 40(%r8), %r15
    movq %r15, 40(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_subtract:
    movq %r10, (%rdi)
    sub (%r8), %r10
    movq %r11, 8(%rdi)
    sbb 8(%r8), %r11
    movq %r12, 16(%rdi)
    sbb 16(%r8), %r12
    movq %r13, 24(%rdi)
    sbb 24(%r8), %r13
    movq %r14, 32(%rdi)
    sbb 32(%r8), %r14
    movq %r15, 40(%rdi)
    sbb 40(%r8), %r15

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_return

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_copy:
    movq %r10, (%rdi)
    movq %r11, 8(%rdi)
    movq %r12, 16(%rdi)
    movq %r13, 24(%rdi)
    movq %r14, 32(%rdi)
    movq %r15, 40(%rdi)

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_montgomery_reduce_final_return:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
