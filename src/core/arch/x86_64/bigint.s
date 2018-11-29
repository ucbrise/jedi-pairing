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

.globl embedded_pairing_core_arch_x86_64_bigint_384_add
.type embedded_pairing_core_arch_x86_64_bigint_384_add, @function
.text

.macro addcarry64 offset
    movq \offset(%rsi), %rax
    adc \offset(%rdx), %rax
    movq %rax, \offset(%rdi)
.endm

embedded_pairing_core_arch_x86_64_bigint_384_add:
    movq (%rsi), %rax
    add (%rdx), %rax
    movq %rax, (%rdi)

    addcarry64 8
    addcarry64 16
    addcarry64 24
    addcarry64 32
    addcarry64 40

    movq $0, %rax
    adc %rax, %rax
    ret

.globl embedded_pairing_core_arch_x86_64_bigint_384_subtract
.type embedded_pairing_core_arch_x86_64_bigint_384_subtract, @function
.text

.macro subborrow64 offset
    movq \offset(%rsi), %rax
    sbb \offset(%rdx), %rax
    movq %rax, \offset(%rdi)
.endm

embedded_pairing_core_arch_x86_64_bigint_384_subtract:
    movq (%rsi), %rax
    sub (%rdx), %rax
    movq %rax, (%rdi)

    subborrow64 8
    subborrow64 16
    subborrow64 24
    subborrow64 32
    subborrow64 40

    sbb %rax, %rax
    neg %rax
    ret

.globl embedded_pairing_core_arch_x86_64_bigint_384_multiply2
.type embedded_pairing_core_arch_x86_64_bigint_384_multiply2, @function
.text

.macro mul2carry64 offset
    movq \offset(%rsi), %rax
    adc %rax, %rax
    movq %rax, \offset(%rdi)
.endm

embedded_pairing_core_arch_x86_64_bigint_384_multiply2:
    movq (%rsi), %rax
    add %rax, %rax
    movq %rax, (%rdi)

    mul2carry64 8
    mul2carry64 16
    mul2carry64 24
    mul2carry64 32
    mul2carry64 40

    movq $0, %rax
    adc %rax, %rax
    ret

.globl embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2
.type embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2, @function
.text

# Destination pointer is in rdi
# Operand 1 pointer is in rsi
# Modulus pointer is in rdx
embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2:
    push %rbx

    # Materialize sum in [rax, rbx, rcx, r8, r9, rsi] (little endian)
    movq (%rsi), %rax
    add %rax, %rax
    movq 8(%rsi), %rbx
    adc %rbx, %rbx
    movq 16(%rsi), %rcx
    adc %rcx, %rcx
    movq 24(%rsi), %r8
    adc %r8, %r8
    movq 32(%rsi), %r9
    adc %r9, %r9
    movq 40(%rsi), %rsi
    adc %rsi, %rsi

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_subtract

    # Try to decide early
    cmp 40(%rdx), %rsi
    jb embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_copy
    jz embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_subtract_compare

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_subtract:
    sub (%rdx), %rax
    movq %rax, (%rdi)
    sbb 8(%rdx), %rbx
    movq %rbx, 8(%rdi)
    sbb 16(%rdx), %rcx
    movq %rcx, 16(%rdi)
    sbb 24(%rdx), %r8
    movq %r8, 24(%rdi)
    sbb 32(%rdx), %r9
    movq %r9, 32(%rdi)
    sbb 40(%rdx), %rsi
    movq %rsi, 40(%rdi)

    pop %rbx
    ret

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_subtract_compare:
    movq %rax, (%rdi)
    sub (%rdx), %rax
    movq %rbx, 8(%rdi)
    sbb 8(%rdx), %rbx
    movq %rcx, 16(%rdi)
    sbb 16(%rdx), %rcx
    movq %r8, 24(%rdi)
    sbb 24(%rdx), %r8
    movq %r9, 32(%rdi)
    sbb 32(%rdx), %r9
    movq %rsi, 40(%rdi)
    sbb 40(%rdx), %rsi

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_return

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_copy:
    movq %rax, (%rdi)
    movq %rbx, 8(%rdi)
    movq %rcx, 16(%rdi)
    movq %r8, 24(%rdi)
    movq %r9, 32(%rdi)
    movq %rsi, 40(%rdi)

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_multiply2_final_return:
    pop %rbx
    ret


.globl embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add
.type embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add, @function
.text

# Destination pointer is in rdi
# Operand 1 pointer is in rsi
# Operand 2 pointer is in rdx
# Modulus pointer is in rcx
embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add:
    push %rbx
    push %rbp

    # Materialize sum in [rax, rbx, rbp, r8, r9, rsi] (little endian)
    movq (%rsi), %rax
    add (%rdx), %rax
    movq 8(%rsi), %rbx
    adc 8(%rdx), %rbx
    movq 16(%rsi), %rbp
    adc 16(%rdx), %rbp
    movq 24(%rsi), %r8
    adc 24(%rdx), %r8
    movq 32(%rsi), %r9
    adc 32(%rdx), %r9
    movq 40(%rsi), %rsi
    adc 40(%rdx), %rsi

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_subtract

    # Try to decide early
    movq 40(%rcx), %rdx
    cmp %rdx, %rsi
    jb embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_copy
    jz embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_subtract_compare

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_subtract:
    sub (%rcx), %rax
    movq %rax, (%rdi)
    sbb 8(%rcx), %rbx
    movq %rbx, 8(%rdi)
    sbb 16(%rcx), %rbp
    movq %rbp, 16(%rdi)
    sbb 24(%rcx), %r8
    movq %r8, 24(%rdi)
    sbb 32(%rcx), %r9
    movq %r9, 32(%rdi)
    sbb 40(%rcx), %rsi
    movq %rsi, 40(%rdi)

    pop %rbp
    pop %rbx
    ret

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_subtract_compare:
    movq %rax, (%rdi)
    sub (%rcx), %rax
    movq %rbx, 8(%rdi)
    sbb 8(%rcx), %rbx
    movq %rbp, 16(%rdi)
    sbb 16(%rcx), %rbp
    movq %r8, 24(%rdi)
    sbb 24(%rcx), %r8
    movq %r9, 32(%rdi)
    sbb 32(%rcx), %r9
    movq %rsi, 40(%rdi)
    sbb %rdx, %rsi

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_return

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_copy:
    movq %rax, (%rdi)
    movq %rbx, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %r8, 24(%rdi)
    movq %r9, 32(%rdi)
    movq %rsi, 40(%rdi)

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_add_final_return:
    pop %rbp
    pop %rbx
    ret

.globl embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_subtract
.type embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_subtract, @function
.text

# Destination pointer is in rdi
# Operand 1 pointer is in rsi
# Operand 2 pointer is in rdx
# Modulus pointer is in rcx
embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_subtract:
    push %rbx
    push %rbp

    # Materialize sum in [rax, rbx, rbp, r8, r9, rsi] (little endian)
    movq (%rsi), %rax
    sub (%rdx), %rax
    movq 8(%rsi), %rbx
    sbb 8(%rdx), %rbx
    movq 16(%rsi), %rbp
    sbb 16(%rdx), %rbp
    movq 24(%rsi), %r8
    sbb 24(%rdx), %r8
    movq 32(%rsi), %r9
    sbb 32(%rdx), %r9
    movq 40(%rsi), %rsi
    sbb 40(%rdx), %rsi

    jc embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_subtract_final_add

    movq %rax, (%rdi)
    movq %rbx, 8(%rdi)
    movq %rbp, 16(%rdi)
    movq %r8, 24(%rdi)
    movq %r9, 32(%rdi)
    movq %rsi, 40(%rdi)

    pop %rbp
    pop %rbx
    ret

embedded_pairing_core_arch_x86_64_montgomeryfpbase_384_subtract_final_add:
    add (%rcx), %rax
    movq %rax, (%rdi)
    adc 8(%rcx), %rbx
    movq %rbx, 8(%rdi)
    adc 16(%rcx), %rbp
    movq %rbp, 16(%rdi)
    adc 24(%rcx), %r8
    movq %r8, 24(%rdi)
    adc 32(%rcx), %r9
    movq %r9, 32(%rdi)
    adc 40(%rcx), %rsi
    movq %rsi, 40(%rdi)

    pop %rbp
    pop %rbx
    ret
