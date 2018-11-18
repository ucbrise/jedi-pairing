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

# Input carry and output carry are in rdx. src1 register is specified as an
# argument, src2 pointer is in rcx, and dst pointer is in rdi.
.macro mulcarry64 src1_reg, src2_off, dst
    movq %rdx, %r8
    movq \src1_reg, %rax
    mulq \src2_off(%rcx)
    add %r8, %rax
    adc $0, %rdx
    movq %rax, \dst
.endm

.macro muladd64 src1_reg, src2_off, dst
    movq \src1_reg, %rax
    mulq \src2_off(%rcx)
    add %rax, \dst
    adc $0, %rdx
.endm

.macro muladdcarry64 src1_reg, src2_off, dst
    movq %rdx, %r8
    movq \src1_reg, %rax
    mulq \src2_off(%rcx)
    add %r8, %rax
    adc $0, %rdx
    add %rax, \dst
    adc $0, %rdx
.endm

.macro multiplyloopiteration i
    movq (8*\i)(%rsi), %r9
    muladd64 %r9, 0, (8*\i)(%rdi)
    muladdcarry64 %r9, 8, (8*\i+8)(%rdi)
    muladdcarry64 %r9, 16, (8*\i+16)(%rdi)
    muladdcarry64 %r9, 24, (8*\i+24)(%rdi)
    muladdcarry64 %r9, 32, (8*\i+32)(%rdi)
    muladdcarry64 %r9, 40, (8*\i+40)(%rdi)
    movq %rdx, (8*\i+48)(%rdi)
.endm

embedded_pairing_core_arch_x86_64_bigint_768_multiply:
    # mul writes result to rdx and rax, so we cannot use rdx as a pointer to
    # the multiplicand. Instead, we use rcx for this purpose. Similarly, we
    # cannot keep the carry in %rdx in-between multiplies, as it needs to be
    # added. So, we use r8 for the carry.
    movq %rdx, %rcx

    movq (%rsi), %r9
    movq %r9, %rax
    mulq (%rcx)
    movq %rax, (%rdi)

    mulcarry64 %r9, 8, 8(%rdi)
    mulcarry64 %r9, 16, 16(%rdi)
    mulcarry64 %r9, 24, 24(%rdi)
    mulcarry64 %r9, 32, 32(%rdi)
    mulcarry64 %r9, 40, 40(%rdi)
    movq %rdx, 48(%rdi)

    multiplyloopiteration 1
    multiplyloopiteration 2
    multiplyloopiteration 3
    multiplyloopiteration 4
    multiplyloopiteration 5

    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply
.type embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply, @function
.text

# Input carry and output carry are in rdx. src1 is in rdx, src2 pointer is in rcx, and dst pointer is in rdi.
.macro mulcarry64_bmi2 src2_off, dst, carry_in, carry_out
    mulx \src2_off(%rcx), %rax, \carry_out
    adc \carry_in, %rax
    movq %rax, \dst
.endm

.macro muladd64_bmi2 src2_off, dst, carry_out
    mulx \src2_off(%rcx), %rax, \carry_out
    add %rax, \dst
.endm

.macro muladdcarry64_bmi2 src2_off, dst, carry_in, carry_out
    mulx \src2_off(%rcx), %rax, \carry_out
    adc \carry_in, %rax
    adc $0, \carry_out
    add %rax, \dst
.endm

.macro multiplyloopiteration_bmi2 i
    movq (8*\i)(%rsi), %rdx
    muladd64_bmi2 0, (8*\i)(%rdi), %r8
    muladdcarry64_bmi2 8, (8*\i+8)(%rdi), %r8, %r9
    muladdcarry64_bmi2 16, (8*\i+16)(%rdi), %r9, %r8
    muladdcarry64_bmi2 24, (8*\i+24)(%rdi), %r8, %r9
    muladdcarry64_bmi2 32, (8*\i+32)(%rdi), %r9, %r8
    muladdcarry64_bmi2 40, (8*\i+40)(%rdi), %r8, %r9
    adc $0, %r9
    movq %r9, (8*\i+48)(%rdi)
.endm

embedded_pairing_core_arch_x86_64_bmi2_bigint_768_multiply:
    push %rbx
    push %rbp
    push %r12
    push %r13
    push %r14
    push %r15
    # mul writes result to rdx and rax, so we cannot use rdx as a pointer to
    # the multiplicand. Instead, we use rcx for this purpose. Similarly, we
    # cannot keep the carry in %rdx in-between multiplies, as it needs to be
    # added. So, we use r8 for the carry.
    movq %rdx, %rcx
    movq (%rsi), %rdx

    mulx (%rcx), %rax, %r8
    movq %rax, (%rdi)

    mulx 8(%rcx), %rax, %r9
    add %r8, %rax
    movq %rax, 8(%rdi)

    mulcarry64_bmi2 16, 16(%rdi), %r9, %r8
    mulcarry64_bmi2 24, 24(%rdi), %r8, %r9
    mulcarry64_bmi2 32, 32(%rdi), %r9, %r8
    mulcarry64_bmi2 40, 40(%rdi), %r8, %r9
    adc $0, %r9
    movq %r9, 48(%rdi)

    multiplyloopiteration_bmi2 1
    multiplyloopiteration_bmi2 2
    multiplyloopiteration_bmi2 3
    multiplyloopiteration_bmi2 4
    multiplyloopiteration_bmi2 5

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbp
    pop %rbx
    ret
