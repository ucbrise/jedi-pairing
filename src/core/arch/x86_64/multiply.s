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

.macro iaca_start
    mov $111, %ebx
    .byte 0x64, 0x67, 0x90
.endm

.macro iaca_end
    mov $222, %ebx
    .byte 0x64, 0x67, 0x90
.endm

# x86_64 calling convention (assuming System V ABI): rdi, rsi, rdx, rcx, r8,
# and r9 are the argument registers, and rax is the return value (also rdx for
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

.macro mul2carry64 x
    movq \x, %rax
    adc %rax, %rax
    movq %rax, \x
.endm

.globl embedded_pairing_core_arch_x86_64_bmi2_bigint_768_square
.type embedded_pairing_core_arch_x86_64_bmi2_bigint_768_square, @function
.text

# rdi is a pointer to the destination BigInt<768>. rsi is a pointers to
# the operand (which is a BigInt<384>).
embedded_pairing_core_arch_x86_64_bmi2_bigint_768_square:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Compute products below diagonal (words (%rdi), 88(%rdi) implicitly zero)

    # Iteration i = 1 (word 8(%rdi) in r10, word 16(%rdi) in r11)
    movq 8(%rsi), %rdx
    mulx (%rsi), %r10, %r11

    # Iteration i = 2 (word 24(%rdi) in r12, word 32(%rdi) in r13)
    movq 16(%rsi), %rdx
    muladd64_bmi2 (%rsi), %r11, %r8
    mulcarry64_bmi2 8(%rsi), %r12, %r8, %r13
    adc $0, %r13

    # Iteration i = 3 (word 40(%rdi) in r14, word 48(%rdi) in r15)
    movq 24(%rsi), %rdx
    muladd64_bmi2 (%rsi), %r12, %r8
    muladdcarry64_bmi2 8(%rsi), %r13, %r8, %r9
    mulcarry64_bmi2 16(%rsi), %r14, %r9, %r15
    adc $0, %r15

    # Iteration i = 4 (word 56(%rdi) in rcx, word 64(%rdi) in rbp)
    movq 32(%rsi), %rdx
    muladd64_bmi2 (%rsi), %r13, %r8
    muladdcarry64_bmi2 8(%rsi), %r14, %r8, %r9
    muladdcarry64_bmi2 16(%rsi), %r15, %r9, %r8
    mulcarry64_bmi2 24(%rsi), %rcx, %r8, %rbp
    adc $0, %rbp

    # Iteration i = 5 (word 72(%rdi) in rbx, word 80(%rdi) in rax)
    movq 40(%rsi), %rdx
    muladd64_bmi2 (%rsi), %r14, %r8
    muladdcarry64_bmi2 8(%rsi), %r15, %r8, %r9
    muladdcarry64_bmi2 16(%rsi), %rcx, %r9, %r8
    muladdcarry64_bmi2 24(%rsi), %rbp, %r8, %r9
    mulcarry64_bmi2 32(%rsi), %rbx, %r9, %rax
    adc $0, %rax

    # Double result (word 88(%rdi) in r9)
    adc %r10, %r10
    adc %r11, %r11
    adc %r12, %r12
    adc %r13, %r13
    adc %r14, %r14
    adc %r15, %r15
    adc %rcx, %rcx
    adc %rbp, %rbp
    adc %rbx, %rbx
    adc %rax, %rax
    movq $0, %r9
    adc $0, %r9

    movq (%rsi), %rdx
    mulx %rdx, %rdx, %r8
    movq %rdx, (%rdi)
    add %r8, %r10
    movq %r10, 8(%rdi)

    movq 8(%rsi), %rdx
    mulx %rdx, %rdx, %r8
    adc %rdx, %r11
    movq %r11, 16(%rdi)
    adc %r8, %r12
    movq %r12, 24(%rdi)

    movq 16(%rsi), %rdx
    mulx %rdx, %rdx, %r8
    adc %rdx, %r13
    movq %r13, 32(%rdi)
    adc %r8, %r14
    movq %r14, 40(%rdi)

    movq 24(%rsi), %rdx
    mulx %rdx, %rdx, %r8
    adc %rdx, %r15
    movq %r15, 48(%rdi)
    adc %r8, %rcx
    movq %rcx, 56(%rdi)

    movq 32(%rsi), %rdx
    mulx %rdx, %rdx, %r8
    adc %rdx, %rbp
    movq %rbp, 64(%rdi)
    adc %r8, %rbx
    movq %rbx, 72(%rdi)

    movq 40(%rsi), %rdx
    mulx %rdx, %rdx, %r8
    adc %rdx, %rax
    movq %rax, 80(%rdi)
    adc %r8, %r9
    movq %r9, 88(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
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
    setc %bl
    add (8*\i+48)(%rsi), \dst0
    adc $0, %rbx
.endm

# Result is stored in rdi, product is in rsi, prime modulus is in rdx, and
# inv_word is in rcx.
embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce:
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    iaca_start

    # Stash the prime modulus in r8, since rdx is used for multiplication
    movq %rdx, %r8

    # Registers r10 to r15 store parts of the product (pointer in rsi)
    movq (%rsi), %r10
    movq 8(%rsi), %r11
    movq 16(%rsi), %r12
    movq 24(%rsi), %r13
    movq 32(%rsi), %r14
    movq 40(%rsi), %r15

    # First iteration
    movq %rcx, %rdx
    imul %r10, %rdx
    montgomeryreduceloopiterationraw_bmi2 0, %r10, %r11, %r12, %r13, %r14, %r15
    adc 48(%rsi), %r10
    movq $0, %rbx
    setc %bl

    # Middle iterations
    montgomeryreduceloopiteration_bmi2 1, %r11, %r12, %r13, %r14, %r15, %r10
    montgomeryreduceloopiteration_bmi2 2, %r12, %r13, %r14, %r15, %r10, %r11
    montgomeryreduceloopiteration_bmi2 3, %r13, %r14, %r15, %r10, %r11, %r12
    montgomeryreduceloopiteration_bmi2 4, %r14, %r15, %r10, %r11, %r12, %r13

    # Final iteration
    movq %rcx, %rdx
    imul %r15, %rdx
    #mulx %r15, %rdx, %rax
    montgomeryreduceloopiterationraw_bmi2 5, %r15, %r10, %r11, %r12, %r13, %r14
    adc %rbx, %r15
    add 88(%rsi), %r15

    # Now, result (sans final reduction) is in r10 to r15, with MSB in r15
    iaca_end

    # Compare, and branch to either copy or subtraction
    cmp 40(%r8), %r15
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract
    cmp 32(%r8), %r14
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract
    cmp 24(%r8), %r13
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract
    cmp 16(%r8), %r12
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract
    cmp 8(%r8), %r11
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract
    cmp (%r8), %r10
    jl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy
    jne embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract

embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_subtract:
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
    ret

embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_montgomery_reduce_final_copy:
    movq %r10, (%rdi)
    movq %r11, 8(%rdi)
    movq %r12, 16(%rdi)
    movq %r13, 24(%rdi)
    movq %r14, 32(%rdi)
    movq %r15, 40(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_multiply
.type embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_multiply, @function
.text

# Destination BigInt<384> pointer is in rdi, operand 1 pointer is in rsi,
# operand 2 pointer is in rdx, prime modulus pointer is in rcx, and inv_word is
# in r8.
embedded_pairing_core_arch_x86_64_bmi2_montgomeryfpbase_384_multiply:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15
    sub 96, %rsp

    # TODO: implement this

    add 96, %rsp
    pop %r15
    pop %r14
    pop %r12
    pop %rbx
    pop %rbp
    ret
