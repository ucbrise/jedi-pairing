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
# and r9 are the arguments registers, and eax is the return value (also edx for
# larger 128-bit return values). The registers rbx, rbp, and r12-r15 must be
# saved and restored by a function if it modifies them.

.globl embedded_pairing_core_arch_x86_64_bigint_768_multiply
.type embedded_pairing_core_arch_x86_64_bigint_768_multiply, @function
.text

# Input carry and output carry are in rdx.
.macro mulcarry64 src1, src2, dst
    movq %rdx, %r8
    movq \src1, %rax
    mulq \src2
    add %r8, %rax
    adc $0, %rdx
    movq %rax, \dst
.endm

.macro muladd64 src1, src2, dst
    movq \src1, %rax
    mulq \src2
    add %rax, \dst
    adc $0, %rdx
.endm

.macro muladdcarry64 src1, src2, dst
    movq %rdx, %r8
    movq \src1, %rax
    mulq \src2
    add %r8, %rax
    adc $0, %rdx
    add %rax, \dst
    adc $0, %rdx
.endm

.macro multiplyloopiteration i, dst0, dst1, dst2, dst3, dst4, dst5
    movq (8*\i)(%rsi), %r9
    muladd64 %r9, (%rcx), \dst0
    movq \dst0, (8*\i)(%rdi)
    muladdcarry64 %r9, 8(%rcx), \dst1
    muladdcarry64 %r9, 16(%rcx), \dst2
    muladdcarry64 %r9, 24(%rcx), \dst3
    muladdcarry64 %r9, 32(%rcx), \dst4
    muladdcarry64 %r9, 40(%rcx), \dst5
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

    mulcarry64 %r9, 8(%rcx), %r10
    mulcarry64 %r9, 16(%rcx), %r11
    mulcarry64 %r9, 24(%rcx), %r12
    mulcarry64 %r9, 32(%rcx), %r13
    mulcarry64 %r9, 40(%rcx), %r14
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

.globl embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply
.type embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply, @function
.text

# Input carry and output carry are in rdx. Extra "+1" bit stored in carry flag.
# src1 is in rdx, src2 pointer is in rcx, and dst pointer is in rdi.
.macro mulcarry64_bmi2 src2, dst, carry_in, carry_out
    mulx \src2, \dst, \carry_out
    adc \carry_in, \dst
.endm

.macro muladd64_bmi2 src2, dst, carry_out
    mulx \src2, %rax, \carry_out
    add %rax, \dst
.endm

.macro muladdcarry64_bmi2 src2, dst, carry_in, carry_out
    mulx \src2, %rax, \carry_out
    # Carry flag was set in previous muladdcarry64_bmi2 or muladd64_bmi2
    adc \carry_in, %rax
    adc $0, \carry_out
    # Carry flag should be zero here, so either add or adc can be used for the
    # next instruction.
    add %rax, \dst
.endm

.macro multiplyloopiteration_bmi2 i, dst0, dst1, dst2, dst3, dst4, dst5
    movq (8*\i)(%rsi), %rdx
    muladd64_bmi2 (%rcx), \dst0, %r8
    movq \dst0, (8*\i)(%rdi)
    # \dst0 is now free, so we use it for carry (along with r8)
    muladdcarry64_bmi2 8(%rcx), \dst1, %r8, \dst0
    muladdcarry64_bmi2 16(%rcx), \dst2, \dst0, %r8
    muladdcarry64_bmi2 24(%rcx), \dst3, %r8, \dst0
    muladdcarry64_bmi2 32(%rcx), \dst4, \dst0, %r8
    muladdcarry64_bmi2 40(%rcx), \dst5, %r8, \dst0
    adc $0, \dst0
.endm

embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply:
    push %r12
    push %r13
    push %r14

    # Register rdx is an implicit source to mulx, so we can't use it to point
    # to the second argument. Instead, we use rcx to point to it.
    movq %rdx, %rcx

    # Register r8 is used for carry.
    # Registers r9 to r14 store parts of the destination array.

    movq (%rsi), %rdx

    mulx (%rcx), %rax, %r8
    movq %rax, (%rdi)

    mulx 8(%rcx), %r9, %r14
    add %r8, %r9

    mulcarry64_bmi2 16(%rcx), %r10, %r14, %r8
    mulcarry64_bmi2 24(%rcx), %r11, %r8, %r14
    mulcarry64_bmi2 32(%rcx), %r12, %r14, %r8
    mulcarry64_bmi2 40(%rcx), %r13, %r8, %r14
    adc $0, %r14

    multiplyloopiteration_bmi2 1, %r9, %r10, %r11, %r12, %r13, %r14
    multiplyloopiteration_bmi2 2, %r10, %r11, %r12, %r13, %r14, %r9
    multiplyloopiteration_bmi2 3, %r11, %r12, %r13, %r14, %r9, %r10
    multiplyloopiteration_bmi2 4, %r12, %r13, %r14, %r9, %r10, %r11
    multiplyloopiteration_bmi2 5, %r13, %r14, %r9, %r10, %r11, %r12

    movq %r14, 48(%rdi)
    movq %r9, 56(%rdi)
    movq %r10, 64(%rdi)
    movq %r11, 72(%rdi)
    movq %r12, 80(%rdi)
    movq %r13, 88(%rdi)

    pop %r14
    pop %r13
    pop %r12
    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce
.type embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce, @function
.text

# The constant u used in multiplications for this iteration should be in rdx
# dst0 to dst5 should contain words i to i + 5 of product (total 12 words)
# At the end, dst1 - dst5 contain words i + 1 to i + 5 of the product
# dst0 is the carry that should be added to word (i+6) with carry bit
.macro montgomeryreduceloopiterationraw_bmi2 i, dst0, dst1, dst2, dst3, dst4, dst5
    muladd64_bmi2 (%r8), \dst0, %r9
    # \dst0 is now free, so we use it for carry (along with r9)
    muladdcarry64_bmi2 8(%r8), \dst1, %r9, \dst0
    muladdcarry64_bmi2 16(%r8), \dst2, \dst0, %r9
    muladdcarry64_bmi2 24(%r8), \dst3, %r9, \dst0
    muladdcarry64_bmi2 32(%r8), \dst4, \dst0, %r9
    muladdcarry64_bmi2 40(%r8), \dst5, %r9, \dst0
.endm

# At the end, dst1 - dst5, dst0 contain words i + 1 to i + 6 of the product
# Carry bit is the "+1" bit for word i+6 (in dst0).
.macro montgomeryreduceloopiteration_bmi2 i, dst0, dst1, dst2, dst3, dst4, dst5
    # Compute u and store it in %rdx
    movq %rcx, %rdx
    imul \dst0, %rdx

    montgomeryreduceloopiterationraw_bmi2 \i, \dst0, \dst1, \dst2, \dst3, \dst4, \dst5

    # Use/store meta-carry in %rbx
    adc %rbx, \dst0
    movq $0, %rbx
    adc $0, %rbx
    add (8*\i+48)(%rsi), \dst0
    adc $0, %rbx
.endm

# Result is stored in rdi, product is in rsi, prime modulus is in rdx, and
# inv_word is in rcx.
embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15

    # Stash the prime modulus in r8, since rdx is used for multiplication
    movq %rdx, %r8

    # Registers r10 to r15 store parts of the product (pointer in rsi)
    movq (%rsi), %r10
    movq 8(%rsi), %r11
    movq 16(%rsi), %r12
    movq 24(%rsi), %r13
    movq 32(%rsi), %r14
    movq 40(%rsi), %r15

    # Clear meta-carry (stored in rbx)
    xor %rbx, %rbx

    # First iteration
    movq %rcx, %rdx
    imul %r10, %rdx
    montgomeryreduceloopiterationraw_bmi2 0, %r10, %r11, %r12, %r13, %r14, %r15
    movq 48(%rsi), %rax
    adc %rax, %r10
    adc $0, %rbx

    # Remaining iterations
    montgomeryreduceloopiteration_bmi2 1, %r11, %r12, %r13, %r14, %r15, %r10
    montgomeryreduceloopiteration_bmi2 2, %r12, %r13, %r14, %r15, %r10, %r11
    montgomeryreduceloopiteration_bmi2 3, %r13, %r14, %r15, %r10, %r11, %r12
    montgomeryreduceloopiteration_bmi2 4, %r14, %r15, %r10, %r11, %r12, %r13
    montgomeryreduceloopiteration_bmi2 5, %r15, %r10, %r11, %r12, %r13, %r14

    movq %r10, 48(%rsi)
    movq %r11, 56(%rsi)
    movq %r12, 64(%rsi)
    movq %r13, 72(%rsi)
    movq %r14, 80(%rsi)
    movq %r15, 88(%rsi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
