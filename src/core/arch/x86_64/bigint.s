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

embedded_pairing_core_arch_x86_64_bigint_384_add:
    movq (%rsi), %rax
    add (%rdx), %rax
    movq %rax, (%rdi)

    movq 8(%rsi), %rax
    adc 8(%rdx), %rax
    movq %rax, 8(%rdi)

    movq 16(%rsi), %rax
    adc 16(%rdx), %rax
    movq %rax, 16(%rdi)

    movq 24(%rsi), %rax
    adc 24(%rdx), %rax
    movq %rax, 24(%rdi)

    movq 32(%rsi), %rax
    adc 32(%rdx), %rax
    movq %rax, 32(%rdi)

    movq 40(%rsi), %rax
    adc 40(%rdx), %rax
    movq %rax, 40(%rdi)

    xor %rax, %rax
    adc %rax, %rax
    ret
