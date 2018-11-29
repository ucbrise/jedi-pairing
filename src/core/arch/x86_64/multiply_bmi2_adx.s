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

.globl embedded_pairing_core_arch_x86_64_cpu_supports_bmi2_adx
.type embedded_pairing_core_arch_x86_64_cpu_supports_bmi2_adx, @function
.text

embedded_pairing_core_arch_x86_64_cpu_supports_bmi2_adx:
    push %rbx

    movl $0x07, %eax
    xor %ecx, %ecx
    cpuid

    # BMI2 support is indicated in bit 8 of ebx
    xor %rax, %rax
    bt $8, %ebx
    adc %rax, %rax

    # ADX support is indicated in bit 19 of ebx
    xor %rcx, %rcx
    bt $19, %ebx
    adc %rcx, %rcx

    # We require support for both BMI2 and ADX to use routines labelled "bmi2"
    and %rcx, %rax

    pop %rbx
    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_multiply
.type embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_multiply, @function
.text

# Input carry and output carry are in rdx. Extra "+1" bit stored in carry flag.
# src1 is in rdx, src2 pointer is in rcx, and dst pointer is in rdi.
.macro mulcarry64_bmi2_adx src2, dst, carry_in, carry_out
    mulx \src2, \dst, \carry_out
    adcx \carry_in, \dst
.endm

.macro muladd64_bmi2_adx src2, dst, carry_out
    mulx \src2, %rax, \carry_out
    adcx %rax, \dst
.endm

.macro muladdcarry64_bmi2_adx src2, dst, carry_in, carry_out
    mulx \src2, %rax, \carry_out
    adox \carry_in, %rax
    adcx %rax, \dst
.endm

.macro multiplyloopiteration_bmi2_adx i, dst0, dst1, dst2, dst3, dst4, dst5, zero
    movq (8*\i)(%rsi), %rdx
    muladd64_bmi2_adx (%rcx), \dst0, %r8
    movq \dst0, (8*\i)(%rdi)
    # \dst0 is now free, so we use it for carry (along with r8)
    muladdcarry64_bmi2_adx 8(%rcx), \dst1, %r8, \dst0
    muladdcarry64_bmi2_adx 16(%rcx), \dst2, \dst0, %r8
    muladdcarry64_bmi2_adx 24(%rcx), \dst3, %r8, \dst0
    muladdcarry64_bmi2_adx 32(%rcx), \dst4, \dst0, %r8
    muladdcarry64_bmi2_adx 40(%rcx), \dst5, %r8, \dst0
    adcx \zero, \dst0
    adox \zero, \dst0
    # At this point, the carry and overflow flags are both 0
.endm

embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_multiply:
    push %rbx
    push %r12
    push %r13
    push %r14

    # Register rdx is an implicit source to mulx, so we can't use it to point
    # to the second argument. Instead, we use rcx to point to it.
    movq %rdx, %rcx

    # Register r8 is used for carry.
    # Registers r9 to r14 store parts of the destination array.
    # rbx is always zero; xor clears carry and overflow flags
    xor %rbx, %rbx

    movq (%rsi), %rdx

    mulx (%rcx), %rax, %r8
    movq %rax, (%rdi)

    mulx 8(%rcx), %r9, %r14
    adcx %r8, %r9

    mulcarry64_bmi2_adx 16(%rcx), %r10, %r14, %r8
    mulcarry64_bmi2_adx 24(%rcx), %r11, %r8, %r14
    mulcarry64_bmi2_adx 32(%rcx), %r12, %r14, %r8
    mulcarry64_bmi2_adx 40(%rcx), %r13, %r8, %r14
    adcx %rbx, %r14
    adox %rbx, %r14

    multiplyloopiteration_bmi2_adx 1, %r9, %r10, %r11, %r12, %r13, %r14, %rbx
    multiplyloopiteration_bmi2_adx 2, %r10, %r11, %r12, %r13, %r14, %r9, %rbx
    multiplyloopiteration_bmi2_adx 3, %r11, %r12, %r13, %r14, %r9, %r10, %rbx
    multiplyloopiteration_bmi2_adx 4, %r12, %r13, %r14, %r9, %r10, %r11, %rbx
    multiplyloopiteration_bmi2_adx 5, %r13, %r14, %r9, %r10, %r11, %r12, %rbx

    movq %r14, 48(%rdi)
    movq %r9, 56(%rdi)
    movq %r10, 64(%rdi)
    movq %r11, 72(%rdi)
    movq %r12, 80(%rdi)
    movq %r13, 88(%rdi)

    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_square
.type embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_square, @function
.text

.macro doubleadddiagonal_bmi2_adx tosquare, todoublelo, todoublehi, storelo, storehi
    movq \tosquare, %rdx
    adcx \todoublelo, \todoublelo
    mulx %rdx, %rdx, %r8
    adox %rdx, \todoublelo
    adcx \todoublehi, \todoublehi
    movq \todoublelo, \storelo
    adox %r8, \todoublehi
    movq \todoublehi, \storehi
.endm

# rdi is a pointer to the destination BigInt<768>. rsi is a pointer to
# the operand (which is a BigInt<384>).
embedded_pairing_core_arch_x86_64_bmi2_adx_bigint_768_square:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Compute products below diagonal (words (%rdi), 88(%rdi) implicitly zero)

    # rbx contains zero until it is used. xor clears carry and overflow flags
    xor %rbx, %rbx

    # Iteration i = 1 (word 8(%rdi) in r10, word 16(%rdi) in r11)
    movq 8(%rsi), %rdx
    mulx (%rsi), %r10, %r11

    # Iteration i = 2 (word 24(%rdi) in r12, word 32(%rdi) in r13)
    movq 16(%rsi), %rdx
    muladd64_bmi2_adx (%rsi), %r11, %r8
    mulcarry64_bmi2_adx 8(%rsi), %r12, %r8, %r13
    adcx %rbx, %r13

    # Iteration i = 3 (word 40(%rdi) in r14, word 48(%rdi) in r15)
    movq 24(%rsi), %rdx
    muladd64_bmi2_adx (%rsi), %r12, %r8
    muladdcarry64_bmi2_adx 8(%rsi), %r13, %r8, %r9
    adox %rbx, %r9
    mulcarry64_bmi2_adx 16(%rsi), %r14, %r9, %r15
    adcx %rbx, %r15

    # Iteration i = 4 (word 56(%rdi) in rcx, word 64(%rdi) in rbp)
    movq 32(%rsi), %rdx
    muladd64_bmi2_adx (%rsi), %r13, %r8
    muladdcarry64_bmi2_adx 8(%rsi), %r14, %r8, %r9
    muladdcarry64_bmi2_adx 16(%rsi), %r15, %r9, %r8
    adox %rbx, %r8
    mulcarry64_bmi2_adx 24(%rsi), %rcx, %r8, %rbp
    adcx %rbx, %rbp

    # Iteration i = 5 (word 72(%rdi) in rbx, word 80(%rdi) in rax)
    movq 40(%rsi), %rdx
    muladd64_bmi2_adx (%rsi), %r14, %r8
    muladdcarry64_bmi2_adx 8(%rsi), %r15, %r8, %r9
    muladdcarry64_bmi2_adx 16(%rsi), %rcx, %r9, %r8
    muladdcarry64_bmi2_adx 24(%rsi), %rbp, %r8, %r9
    adox %rbx, %r9
    mulcarry64_bmi2_adx 32(%rsi), %rbx, %r9, %rax
    movq $0, %rdx
    adcx %rdx, %rax

    # Double result (word 88(%rdi) in r9) and add diagonal
    xor %r9, %r9

    movq (%rsi), %rdx
    adcx %r10, %r10
    mulx %rdx, %rdx, %r8
    movq %rdx, (%rdi)
    adox %r8, %r10
    movq %r10, 8(%rdi)

    doubleadddiagonal_bmi2_adx 8(%rsi), %r11, %r12, 16(%rdi), 24(%rdi)
    doubleadddiagonal_bmi2_adx 16(%rsi), %r13, %r14, 32(%rdi), 40(%rdi)
    doubleadddiagonal_bmi2_adx 24(%rsi), %r15, %rcx, 48(%rdi), 56(%rdi)
    doubleadddiagonal_bmi2_adx 32(%rsi), %rbp, %rbx, 64(%rdi), 72(%rdi)
    doubleadddiagonal_bmi2_adx 40(%rsi), %rax, %r9, 80(%rdi), 88(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret

.globl embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce
.type embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce, @function
.text

# The constant u used in multiplications for this iteration should be in rdx
# dst0 to dst5 should contain words i to i + 5 of product (total 12 words)
# At the end, dst1 - dst5 contain words i + 1 to i + 5 of the product
# dst0 is the carry that should be added to word (i+6) with carry bit
.macro montgomeryreduceloopiterationraw_bmi2_adx i, dst0, dst1, dst2, dst3, dst4, dst5
    muladd64_bmi2_adx (%rbp), \dst0, %rcx
    # \dst0 is now free, so we use it for carry (along with rcx)
    muladdcarry64_bmi2_adx 8(%rbp), \dst1, %rcx, \dst0
    muladdcarry64_bmi2_adx 16(%rbp), \dst2, \dst0, %rcx
    muladdcarry64_bmi2_adx 24(%rbp), \dst3, %rcx, \dst0
    muladdcarry64_bmi2_adx 32(%rbp), \dst4, \dst0, %rcx
    muladdcarry64_bmi2_adx 40(%rbp), \dst5, %rcx, \dst0
.endm

# At the end, dst1 - dst5, dst0 contain words i + 1 to i + 6 of the product
# Carry bit is the "+1" bit for word i + 6 (in dst0).
.macro montgomeryreduceloopiteration_bmi2_adx i, dst0, dst1, dst2, dst3, dst4, dst5
    # Compute u and store it in %rdx
    movq %r9, %rdx
    mulx \dst0, %rdx, %rax

    setc %bl
    cmovo %r8, %rbx
    xor %rax, %rax
    # Now, the carry and overflow flags are both zero

    montgomeryreduceloopiterationraw_bmi2_adx \i, \dst0, \dst1, \dst2, \dst3, \dst4, \dst5

    # Use/store meta-carry in %rbx
    adox (8*\i+48)(%rsi), \dst0
    adcx %rbx, \dst0
.endm

# Result is stored in rdi, product is in rsi, prime modulus is in rdx, and
# inv_word is in rcx.
embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce:
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Registers r10 to r15 store parts of the product (pointer in rsi)
    movq (%rsi), %r10
    movq 8(%rsi), %r11
    movq 16(%rsi), %r12
    movq 24(%rsi), %r13
    movq 32(%rsi), %r14
    movq 40(%rsi), %r15

    # Stash the prime modulus in rbp, since rdx is used for multiplication
    movq %rdx, %rbp

    # First iteration
    movq %rcx, %rdx
    mulx %r10, %rdx, %rax

    # rcx is used for carry, so all future iterations get inv_word from r9
    movq %rcx, %r9

    # rbx is used for meta-carry. xor clears carry and overflow flags
    # rb8 just contains 1
    movq $1, %r8
    xor %rbx, %rbx

    montgomeryreduceloopiterationraw_bmi2_adx 0, %r10, %r11, %r12, %r13, %r14, %r15
    adox 48(%rsi), %r10
    adcx %rbx, %r10

    # Middle iterations
    montgomeryreduceloopiteration_bmi2_adx 1, %r11, %r12, %r13, %r14, %r15, %r10
    montgomeryreduceloopiteration_bmi2_adx 2, %r12, %r13, %r14, %r15, %r10, %r11
    montgomeryreduceloopiteration_bmi2_adx 3, %r13, %r14, %r15, %r10, %r11, %r12
    montgomeryreduceloopiteration_bmi2_adx 4, %r14, %r15, %r10, %r11, %r12, %r13

    # Final iteration
    movq %r9, %rdx
    mulx %r15, %rdx, %rax

    setc %bl
    cmovo %r8, %rbx
    xor %rax, %rax

    montgomeryreduceloopiterationraw_bmi2_adx 5, %r15, %r10, %r11, %r12, %r13, %r14
    adox 88(%rsi), %r15
    adcx %rbx, %r15

    # Now, result (sans final reduction) is in r10 to r15, with MSB in r15

    # Compare, and branch to either copy or subtraction
    cmp 40(%rbp), %r15
    jb embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_copy
    je embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_subtract_compare

embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_subtract:
    sub (%rbp), %r10
    movq %r10, (%rdi)
    sbb 8(%rbp), %r11
    movq %r11, 8(%rdi)
    sbb 16(%rbp), %r12
    movq %r12, 16(%rdi)
    sbb 24(%rbp), %r13
    movq %r13, 24(%rdi)
    sbb 32(%rbp), %r14
    movq %r14, 32(%rdi)
    sbb 40(%rbp), %r15
    movq %r15, 40(%rdi)

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret

embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_subtract_compare:
    movq %r10, (%rdi)
    sub (%rbp), %r10
    movq %r11, 8(%rdi)
    sbb 8(%rbp), %r11
    movq %r12, 16(%rdi)
    sbb 16(%rbp), %r12
    movq %r13, 24(%rdi)
    sbb 24(%rbp), %r13
    movq %r14, 32(%rdi)
    sbb 32(%rbp), %r14
    movq %r15, 40(%rdi)
    sbb 40(%rbp), %r15

    jc embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_return

embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_copy:
    movq %r10, (%rdi)
    movq %r11, 8(%rdi)
    movq %r12, 16(%rdi)
    movq %r13, 24(%rdi)
    movq %r14, 32(%rdi)
    movq %r15, 40(%rdi)

embedded_pairing_core_arch_x86_64_bmi2_adx_fpbase_384_montgomery_reduce_final_return:
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    ret
