@ Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
@ Copyright (c) 2018, University of California, Berkeley
@ All rights reserved.
@
@ Redistribution and use in source and binary forms, with or without
@ modification, are permitted provided that the following conditions are met:
@
@ 1. Redistributions of source code must retain the above copyright notice,
@    this list of conditions and the following disclaimer.
@
@ 2. Redistributions in binary form must reproduce the above copyright notice,
@    this list of conditions and the following disclaimer in the documentation
@    and/or other materials provided with the distribution.
@
@ 3. Neither the name of the copyright holder nor the names of its
@    contributors may be used to endorse or promote products derived from
@    this software without specific prior written permission.
@
@ THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
@ AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
@ IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
@ ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
@ LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
@ CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
@ SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
@ INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
@ CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
@ ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
@ POSSIBILITY OF SUCH DAMAGE.

@ ARM calling convention: registers r0 to r3 are temporary, but registers
@ r4 to r12 must be saved if modified. Arguments are r0 to r3, and return
@ value goes in r0.

.globl embedded_pairing_core_arch_armv6_m_bigint_384_add
.type embedded_pairing_core_arch_armv6_m_bigint_384_add, %function
.text
.thumb

.macro addcarry64 dst, src0, src1
    ldm \src0!, {r3, r4}
    ldm \src1!, {r5, r6}
    adc r3, r3, r5
    adc r4, r4, r6
    stm \dst!, {r3, r4}
.endm

@ r0 contains a pointer to the BigInt where the result should be stored
@ r1 contains a pointer to operand "a"
@ r2 contains a pointer to operand "b"
embedded_pairing_core_arch_armv6_m_bigint_384_add:
    @ Save registers
    push {r4, r5, r6}

    ldm r1!, {r3, r4}
    ldm r2!, {r5, r6}
    add r3, r3, r5
    adc r4, r4, r6
    stm r0!, {r3, r4}

    addcarry64 r0, r1, r2
    addcarry64 r0, r1, r2
    addcarry64 r0, r1, r2
    addcarry64 r0, r1, r2
    addcarry64 r0, r1, r2

    @ Recover carry bit and store it in r0
    eor r0, r0, r0
    adc r0, r0, r0

    @ Restore registers and return
    pop {r4, r5, r6}
    bx lr

.globl embedded_pairing_core_arch_armv6_m_bigint_384_subtract
.type embedded_pairing_core_arch_armv6_m_bigint_384_subtract, %function
.text
.thumb

.macro subcarry64 dst, src0, src1
    ldm \src0!, {r3, r4}
    ldm \src1!, {r5, r6}
    sbc r3, r3, r5
    sbc r4, r4, r6
    stm \dst!, {r3, r4}
.endm

@ r0 contains a pointer to the BigInt where the result should be stored
@ r1 contains a pointer to operand "a"
@ r2 contains a pointer to operand "b"
embedded_pairing_core_arch_armv6_m_bigint_384_subtract:
    @ Save registers
    push {r4, r5, r6}

    ldm r1!, {r3, r4}
    ldm r2!, {r5, r6}
    sub r3, r3, r5
    sbc r4, r4, r6
    stm r0!, {r3, r4}

    subcarry64 r0, r1, r2
    subcarry64 r0, r1, r2
    subcarry64 r0, r1, r2
    subcarry64 r0, r1, r2
    subcarry64 r0, r1, r2

    @ Recover carry bit and store it in r0
    sbc r0, r0, r0
    neg r0, r0

    @ Restore registers and return
    pop {r4, r5, r6}
    bx lr

.globl embedded_pairing_core_arch_armv6_m_bigint_384_multiply2
.type embedded_pairing_core_arch_armv6_m_bigint_384_multiply2, %function
.text
.thumb

@ r0 contains a pointer to the BigInt where the result should be stored
@ r1 contains a pointer to the BigInt to double
embedded_pairing_core_arch_armv6_m_bigint_384_multiply2:
    @ Save registers
    push {r4, r5}

    ldm r1!, {r2, r3, r4, r5}
    add r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    stm r0!, {r2, r3, r4, r5}

    ldm r1!, {r2, r3, r4, r5}
    adc r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    stm r0!, {r2, r3, r4, r5}

    ldm r1!, {r2, r3, r4, r5}
    adc r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    stm r0!, {r2, r3, r4, r5}

    @ Recover carry bit and store it in r0
    eor r0, r0, r0
    adc r0, r0, r0

    @ Restore registers and return
    pop {r4, r5}
    bx lr
