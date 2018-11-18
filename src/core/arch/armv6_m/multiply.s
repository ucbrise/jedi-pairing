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

.globl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_multiply
.type embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_multiply, %function
.text
.thumb

@ We already implemented BigInt multiply in bigint.s, but for montgomery
@ reduction, our destination BigInt<768> is allocated on the stack. This allows
@ us to do the multiplication more efficiently, as we can access the
@ destination relative to sp, freeing up one more general-purpose register. As
@ a result, we don't have to spill to r8.

@ The macro multiply32 computes the product of two BigInt<384>s pointed to
@ by r1 and r2 and stores them in the BigInt<768> pointed to by sp. As before,
@ we split this into three parts so that additions can be done efficiently in
@ the middle.

@ Unlike in bigint.s, the macros take in a "scratch" argument that allows the
@ caller to choose one register \s to use for scratch space. The register used
@ are \s, r4, r5, r6, and r7. The scratch register can be chosen wisely to
@ avoid having to move the carry between calls to the macro. The output carry
@ is written to the scratch register.

.macro multiply32part1 a1, a2, s
    uxth r5, \a1 @ lower half of a, denoted a0
    uxth r6, \a2 @ lower half of b, denoted b0
    lsr r4, \a1, #16 @ upper half of a, denoted a1
    lsr \s, \a2, #16 @ upper half of b, denoted b1
    mov r7, r6

    mul r6, r5, r6 @ a0 * b0
    mul r5, r5, \s @ a0 * b1
    mul \s, \s, r4 @ a1 * b1
    mul r4, r4, r7 @ a1 * b0

    @ Add (a0 * b1 + a1 * b0), store carry in r5
    add r4, r4, r5
    eor r5, r5, r5
    adc r5, r5, r5
.endm

.macro multiply32part2
    @ Move carry to top half of r5
    lsl r5, r5, #16
.endm

.macro multiply32part3 s
    @ Add carry from (r4 + r5) to top half of top result (\s)
    @ Using adc provides a "free" carry for code between the two halves
    adc \s, \s, r5

    @ Split the sum (r4 + r5) into top half of bottom and bottom half of top
    lsl r5, r4, #16
    lsr r4, r4, #16
    add r6, r6, r5
    adc \s, \s, r4
.endm

.macro multiply32 a1, a2, s
    multiply32part1 \a1, \a2, \s
    multiply32part2
    multiply32part3 \s
.endm

@ Same as multiply32, except that it receives an input carry in \carry.
.macro mulcarry32 a1, a2, s, carry
    multiply32part1 \a1, \a2, \s
    multiply32part2

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    @ The multiply32secondhalf macro begins with adc and does the carry to r3
    add r6, r6, \carry

    multiply32part3 \s
.endm

@ The macro muladd32 multiplies words at the specified offets from r1 and r2,
@ adds it to the word at the specified offset from r0, and stores the result
@ at that same offset.
.macro muladd32 a1, a2, dst_off, s
    multiply32part1 \a1, \a2, \s
    multiply32part2

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    @ The multiply32secondhalf macro begins with adc and does the carry to r3
    ldr r7, [sp, #\dst_off]
    add r6, r6, r7

    multiply32part3 \s
.endm

@ The macro muladdcarry32 is the same as muladd32, except that it also accepts
@ an input carry, added to the result, in the register r8.
.macro muladdcarry32 a1, a2, dst_off, s, carry
    multiply32part1 \a1, \a2, \s

    @ Handle the input carry. The carry after adding to the lower result is
    @ handled by adding it to r5, which is anyway going to be added to \a. The
    @ advantage to doing this is that we don't need to spend a cycle obtaining
    @ a zero register to extract the carry bit. Basically, we customize
    @ multiply32part2 to save this cycle.
    lsl r5, r5, #15 @ Note we only shift left by 15 bits; this will be doubled
    add r6, r6, \carry
    adc r5, r5, r5 @ We double r5 and add the carry bit

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    ldr r7, [sp, #\dst_off]
    add r6, r6, r7

    multiply32part3 \s
.endm

.macro multiplyloopiteration i
    ldr r4, [r1, #4*\i]
    mov r10, r4
    ldr r3, [r2, #0]
    muladd32 r4, r3, 4*\i, r3
    str r6, [sp, #4*\i]

    mov r4, r10
    ldr r0, [r2, #4]
    muladdcarry32 r4, r0, 4*\i+4, r0, r3
    str r6, [sp, #4*\i+4]

    mov r4, r10
    ldr r3, [r2, #8]
    muladdcarry32 r4, r3, 4*\i+8, r3, r0
    str r6, [sp, #4*\i+8]

    mov r4, r10
    ldr r0, [r2, #12]
    muladdcarry32 r4, r0, 4*\i+12, r0, r3
    str r6, [sp, #4*\i+12]

    mov r4, r10
    ldr r3, [r2, #16]
    muladdcarry32 r4, r3, 4*\i+16, r3, r0
    str r6, [sp, #4*\i+16]

    mov r4, r10
    ldr r0, [r2, #20]
    muladdcarry32 r4, r0, 4*\i+20, r0, r3
    str r6, [sp, #4*\i+20]

    mov r4, r10
    ldr r3, [r2, #24]
    muladdcarry32 r4, r3, 4*\i+24, r3, r0
    str r6, [sp, #4*\i+24]

    mov r4, r10
    ldr r0, [r2, #28]
    muladdcarry32 r4, r0, 4*\i+28, r0, r3
    str r6, [sp, #4*\i+28]

    mov r4, r10
    ldr r3, [r2, #32]
    muladdcarry32 r4, r3, 4*\i+32, r3, r0
    str r6, [sp, #4*\i+32]

    mov r4, r10
    ldr r0, [r2, #36]
    muladdcarry32 r4, r0, 4*\i+36, r0, r3
    str r6, [sp, #4*\i+36]

    mov r4, r10
    ldr r3, [r2, #40]
    muladdcarry32 r4, r3, 4*\i+40, r3, r0
    str r6, [sp, #4*\i+40]

    mov r4, r10
    ldr r0, [r2, #44]
    muladdcarry32 r4, r0, 4*\i+44, r0, r3
    str r6, [sp, #4*\i+44]

    str r0, [sp, #4*\i+48]
.endm

.macro montgomeryreduceloopiterationraw i
    ldr r3, [r1, #0]
    muladd32 r2, r3, 4*\i, r3
    @ Skip store for j = 0; correct to do it, but not needed

    ldr r0, [r1, #4]
    muladdcarry32 r2, r0, 4*\i+4, r0, r3
    str r6, [sp, #4*\i+4]

    ldr r3, [r1, #8]
    muladdcarry32 r2, r3, 4*\i+8, r3, r0
    str r6, [sp, #4*\i+8]

    ldr r0, [r1, #12]
    muladdcarry32 r2, r0, 4*\i+12, r0, r3
    str r6, [sp, #4*\i+12]

    ldr r3, [r1, #16]
    muladdcarry32 r2, r3, 4*\i+16, r3, r0
    str r6, [sp, #4*\i+16]

    ldr r0, [r1, #20]
    muladdcarry32 r2, r0, 4*\i+20, r0, r3
    str r6, [sp, #4*\i+20]

    ldr r3, [r1, #24]
    muladdcarry32 r2, r3, 4*\i+24, r3, r0
    str r6, [sp, #4*\i+24]

    ldr r0, [r1, #28]
    muladdcarry32 r2, r0, 4*\i+28, r0, r3
    str r6, [sp, #4*\i+28]

    ldr r3, [r1, #32]
    muladdcarry32 r2, r3, 4*\i+32, r3, r0
    str r6, [sp, #4*\i+32]

    ldr r0, [r1, #36]
    muladdcarry32 r2, r0, 4*\i+36, r0, r3
    str r6, [sp, #4*\i+36]

    ldr r3, [r1, #40]
    muladdcarry32 r2, r3, 4*\i+40, r3, r0
    str r6, [sp, #4*\i+40]

    ldr r0, [r1, #44]
    muladdcarry32 r2, r0, 4*\i+44, r0, r3
    str r6, [sp, #4*\i+44]
.endm

.macro montgomeryreduceloopiteration i
    mov r2, r9
    ldr r3, [sp, #4*\i]
    mul r2, r2, r3

    montgomeryreduceloopiterationraw \i

    @ Recover the meta-carry from r8
    mov r3, r8
    lsr r3, r3, #1

    @ Add, including the old meta-carry
    ldr r3, [sp, #4*\i+48]
    adc r0, r0, r3
    str r0, [sp, #4*\i+48]

    @ Get the new meta-carry and stash it in the least-significant bit of r8
    adc r3, r3, r3
    mov r8, r3
.endm

@ Registers r1 and r2 must contain pointers to the BigInt<384>s to multiply.
@ Result is materialized in the BigInt<768> that sp points to
.macro multiply768
    @ Iteration i = 0
    ldr r4, [r1, #0]
    mov r10, r4
    ldr r3, [r2, #0]
    multiply32 r4, r3, r3
    str r6, [sp, #0]

    mov r4, r10
    ldr r0, [r2, #4]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #4]

    mov r4, r10
    ldr r3, [r2, #8]
    mulcarry32 r4, r3, r3, r0
    str r6, [sp, #8]

    mov r4, r10
    ldr r0, [r2, #12]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #12]

    mov r4, r10
    ldr r3, [r2, #16]
    mulcarry32 r4, r3, r3, r0
    str r6, [sp, #16]

    mov r4, r10
    ldr r0, [r2, #20]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #20]

    mov r4, r10
    ldr r3, [r2, #24]
    mulcarry32 r4, r3, r3, r0
    str r6, [sp, #24]

    mov r4, r10
    ldr r0, [r2, #28]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #28]

    mov r4, r10
    ldr r3, [r2, #32]
    mulcarry32 r4, r3, r3, r0
    str r6, [sp, #32]

    mov r4, r10
    ldr r0, [r2, #36]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #36]

    mov r4, r10
    ldr r3, [r2, #40]
    mulcarry32 r4, r3, r3, r0
    str r6, [sp, #40]

    mov r4, r10
    ldr r0, [r2, #44]
    mulcarry32 r4, r0, r0, r3
    str r6, [sp, #44]

    str r0, [sp, #48]

    @ Multiplication, iterations i = 1 to 11
    multiplyloopiteration 1
    multiplyloopiteration 2
    multiplyloopiteration 3
    multiplyloopiteration 4
    multiplyloopiteration 5
    multiplyloopiteration 6
    multiplyloopiteration 7
    multiplyloopiteration 8
    multiplyloopiteration 9
    multiplyloopiteration 10
    multiplyloopiteration 11
.endm

@ Register r1 contains the prime modulus
@ Registers r9 and r2 both contain the inv_word
@ Register r8 is used as scratch (along with r2-r7)
@ The result is materialized in the upper half of the BigIt<768> pointed to by
@ sp. This does not perform the final step: copying the upper half of the
@ BigInt<384> into this, and subtracting p from it if necessary.
.macro montgomeryreduce384
    @ Montgomery reduction, iteration i = 0
    ldr r3, [sp, #0]
    mul r2, r2, r3
    montgomeryreduceloopiterationraw 0

    ldr r3, [sp, #48]
    add r0, r0, r3
    str r0, [sp, #48]

    @ Recover the carry from that add (the meta-carry) and move it to LSB of r8
    adc r3, r3, r3
    mov r8, r3

    @ Montgomery reduction, iterations i = 1 to 10
    montgomeryreduceloopiteration 1
    montgomeryreduceloopiteration 2
    montgomeryreduceloopiteration 3
    montgomeryreduceloopiteration 4
    montgomeryreduceloopiteration 5
    montgomeryreduceloopiteration 6
    montgomeryreduceloopiteration 7
    montgomeryreduceloopiteration 8
    montgomeryreduceloopiteration 9
    montgomeryreduceloopiteration 10

    @ Montgomery reduction, iteration i = 11
    mov r2, r9
    ldr r3, [sp, #44]
    mul r2, r2, r3
    montgomeryreduceloopiterationraw 11

    @ Recover the meta-carry from r8
    mov r3, r8
    lsr r3, r3, #1

    @ Add, including the old meta-carry
    ldr r3, [sp, #92]
    adc r0, r0, r3
    str r0, [sp, #92]
.endm

.globl embedded_pairing_core_arch_armv6_m_bigint_768_multiply
.type embedded_pairing_core_arch_armv6_m_bigint_768_multiply, %function
.text
.thumb

embedded_pairing_core_arch_armv6_m_bigint_768_multiply:
    @ Save registers
    push {r4, r5, r6, r7, lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4, r5, r6, r7}

    @ Store p and inv in r8 and r9, until we need them after the multiplication
    mov r8, r3
    ldr r4, [sp, #36]
    mov r9, r4

    @ Store this in r11, until we need it for the final reduction
    mov r11, r0

    @ Allocate space for temporary BigInt<768> "tmp" storing the product
    sub sp, sp, #96

    @ Compute the product of a * b and store it in tmp

    multiply768

    @ Copy result from tmp into this

    mov r0, r11
    mov r1, sp

    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}

    @ Deallocate space for temporary BigInt<768> "tmp"
    add sp, sp, #96

    @ Restore registers
    pop {r4, r5, r6, r7}
    mov r11, r7
    mov r10, r6
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7, pc}

@ r0 contains a pointer to the MontgomeryFpBase where to store the final result
@ r1 contains a pointer to operand "a"
@ r2 contains a pointer to operand "b"
@ r3 contains a pointer to the modulus "p"
@ First element on stack is the "inv" value for Montgomery Reduction
embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_multiply:
    @ Save registers
    push {r4, r5, r6, r7, lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4, r5, r6, r7}

    @ Store p in r8, until we need it for montgomery reduction
    mov r8, r3

    @ Store this in r11, until we need it for the final reduction
    mov r11, r0

    @ Allocate space for temporary BigInt<768> "tmp" storing the product
    sub sp, sp, #96

    @ Compute the product of a * b and store it in tmp

    multiply768

    @ Perform Montgomery Reduction on tmp
    mov r1, r8 @ We bring p to r1; now r8 is used for the meta-carry

    ldr r2, [sp, #132]
    mov r9, r2
    montgomeryreduce384

    @ Final step of Montgomery Reduction
    mov r0, r11
    mov r2, r1
    add r1, sp, #48
    bl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_reduce

    @ Deallocate space for temporary BigInt<768> "tmp"
    add sp, sp, #96

    @ Restore registers
    pop {r4, r5, r6, r7}
    mov r11, r7
    mov r10, r6
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7, pc}


.globl embedded_pairing_core_arch_armv6_m_bigint_768_square
.type embedded_pairing_core_arch_armv6_m_bigint_768_square, %function
.text
.thumb

@ Specialized multiply macro for squaring a single number this is advantageous
@ over multiply32part1 because (1) it executes faster, and (2) preserves r3
.macro square32part1 a, s
    uxth r6, \a @ lower half of a, denoted b0
    lsr \s, \a, #16 @ upper half of a, denoted b1
    mov r4, r6

    mul r6, r6, r6 @ a0 * a0
    mul r4, r4, \s @ a1 * a0
    mul \s, \s, \s @ a1 * a1

    @ Add (a0 * b1 + a1 * b0), store carry in r5
    add r4, r4, r4
    eor r5, r5, r5
    adc r5, r5, r5
.endm

.macro squareadd32 a, dst_off, s
    square32part1 \a, \s
    multiply32part2

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    @ The multiply32secondhalf macro begins with adc and does the carry to r3
    ldr r7, [sp, #\dst_off]
    add r6, r6, r7

    multiply32part3 \s
.endm

.macro squareaddcarry32 a, dst_off, s, carry
    square32part1 \a, \s

    lsl r5, r5, #15
    add r6, r6, \carry
    adc r5, r5, r5

    ldr r7, [sp, #\dst_off]
    add r6, r6, r7

    multiply32part3 \s
.endm

@ Usually used for j = 0
.macro squareloopiterationfirst i, j, data
    ldr \data, [r1, #4*\j]
    muladd32 r2, \data, 4*(\i+\j), \data
    str r6, [sp, #4*(\i+\j)]
.endm

.macro squareloopiteration i, j, data, carry
    ldr \data, [r1, #4*\j]
    muladdcarry32 r2, \data, 4*(\i+\j), \data, \carry
    str r6, [sp, #4*(\i+\j)]
.endm

.macro squareloopiterationlast i, j, data, carry
    ldr \data, [r1, #4*\j]
    mulcarry32 r2, \data, \data, \carry
    str r6, [sp, #4*(\i+\j)]
.endm

.macro squarediagonaliteration i
    ldr r2, [r1, #4*\i]
    squareaddcarry32 r2, 8*\i, r2, r0
    str r6, [sp, #8*\i]
    ldr r6, [sp, #8*\i+4]
    add r6, r6, r2
    str r6, [sp, #8*\i+4]
    eor r0, r0, r0
    adc r0, r0, r0
.endm

@ r1 must point to the BigInt<384> we're trying to square
@ result is materialized into the BigInt<768> pointed to by sp
@ lowest and highest words are implicitly zero, and remain untouched
.macro square768part1
    @ i = 1
    ldr r2, [r1, #4]
    ldr r3, [r1, #0]
    multiply32 r2, r3, r3
    str r6, [sp, #4]
    str r3, [sp, #8]

    @ i = 2
    ldr r2, [r1, #8]
    squareloopiterationfirst 2, 0, r3
    squareloopiterationlast 2, 1, r0, r3
    str r0, [sp, #16]

    @ i = 3
    ldr r2, [r1, #12]
    squareloopiterationfirst 3, 0, r3
    squareloopiteration 3, 1, r0, r3
    squareloopiterationlast 3, 2, r3, r0
    str r3, [sp, #24]

    @ i = 4
    ldr r2, [r1, #16]
    squareloopiterationfirst 4, 0, r3
    squareloopiteration 4, 1, r0, r3
    squareloopiteration 4, 2, r3, r0
    squareloopiterationlast 4, 3, r0, r3
    str r0, [sp, #32]

    @ i = 5
    ldr r2, [r1, #20]
    squareloopiterationfirst 5, 0, r3
    squareloopiteration 5, 1, r0, r3
    squareloopiteration 5, 2, r3, r0
    squareloopiteration 5, 3, r0, r3
    squareloopiterationlast 5, 4, r3, r0
    str r3, [sp, #40]

    @ i = 6
    ldr r2, [r1, #24]
    squareloopiterationfirst 6, 0, r3
    squareloopiteration 6, 1, r0, r3
    squareloopiteration 6, 2, r3, r0
    squareloopiteration 6, 3, r0, r3
    squareloopiteration 6, 4, r3, r0
    squareloopiterationlast 6, 5, r0, r3
    str r0, [sp, #48]

    @ i = 7
    ldr r2, [r1, #28]
    squareloopiterationfirst 7, 0, r3
    squareloopiteration 7, 1, r0, r3
    squareloopiteration 7, 2, r3, r0
    squareloopiteration 7, 3, r0, r3
    squareloopiteration 7, 4, r3, r0
    squareloopiteration 7, 5, r0, r3
    squareloopiterationlast 7, 6, r3, r0
    str r3, [sp, #56]

    @ i = 8
    ldr r2, [r1, #32]
    squareloopiterationfirst 8, 0, r3
    squareloopiteration 8, 1, r0, r3
    squareloopiteration 8, 2, r3, r0
    squareloopiteration 8, 3, r0, r3
    squareloopiteration 8, 4, r3, r0
    squareloopiteration 8, 5, r0, r3
    squareloopiteration 8, 6, r3, r0
    squareloopiterationlast 8, 7, r0, r3
    str r0, [sp, #64]

    @ i = 9
    ldr r2, [r1, #36]
    squareloopiterationfirst 9, 0, r3
    squareloopiteration 9, 1, r0, r3
    squareloopiteration 9, 2, r3, r0
    squareloopiteration 9, 3, r0, r3
    squareloopiteration 9, 4, r3, r0
    squareloopiteration 9, 5, r0, r3
    squareloopiteration 9, 6, r3, r0
    squareloopiteration 9, 7, r0, r3
    squareloopiterationlast 9, 8, r3, r0
    str r3, [sp, #72]

    @ i = 10
    ldr r2, [r1, #40]
    squareloopiterationfirst 10, 0, r3
    squareloopiteration 10, 1, r0, r3
    squareloopiteration 10, 2, r3, r0
    squareloopiteration 10, 3, r0, r3
    squareloopiteration 10, 4, r3, r0
    squareloopiteration 10, 5, r0, r3
    squareloopiteration 10, 6, r3, r0
    squareloopiteration 10, 7, r0, r3
    squareloopiteration 10, 8, r3, r0
    squareloopiterationlast 10, 9, r0, r3
    str r0, [sp, #80]

    @ i = 11
    ldr r2, [r1, #44]
    squareloopiterationfirst 11, 0, r3
    squareloopiteration 11, 1, r0, r3
    squareloopiteration 11, 2, r3, r0
    squareloopiteration 11, 3, r0, r3
    squareloopiteration 11, 4, r3, r0
    squareloopiteration 11, 5, r0, r3
    squareloopiteration 11, 6, r3, r0
    squareloopiteration 11, 7, r0, r3
    squareloopiteration 11, 8, r3, r0
    squareloopiteration 11, 9, r0, r3
    squareloopiterationlast 11, 10, r3, r0
    str r3, [sp, #88]
.endm

@ This doubles the value of sp, but overwrites r0 and r1 in doing so...
.macro square768part2
    add r0, sp, #4
    mov r1, sp
    ldm r0!, {r3-r7}
    eor r2, r2, r2 @ Bottom word not set by square768part1 but is implicitly 0
    add r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    adc r6, r6, r6
    adc r7, r7, r7
    stm r1!, {r2-r7}
    ldm r0!, {r2-r7}
    adc r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    adc r6, r6, r6
    adc r7, r7, r7
    stm r1!, {r2-r7}
    ldm r0!, {r2-r7}
    adc r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    adc r6, r6, r6
    adc r7, r7, r7
    stm r1!, {r2-r7}
    ldm r0!, {r2-r6}
    adc r2, r2, r2
    adc r3, r3, r3
    adc r4, r4, r4
    adc r5, r5, r5
    adc r6, r6, r6
    eor r7, r7, r7 @ Top word is not set by square768part1 but is implicitly 0
    adc r7, r7, r7
    stm r1!, {r2-r7}
.endm

@ r1 must point to the BigInt<384> we're trying to square
.macro square768part3
    ldr r2, [r1, #0]
    squareadd32 r2, 0, r2
    str r6, [sp, #0]
    ldr r6, [sp, #4]
    add r6, r6, r2
    str r6, [sp, #4]
    eor r0, r0, r0
    adc r0, r0, r0

    squarediagonaliteration 1
    squarediagonaliteration 2
    squarediagonaliteration 3
    squarediagonaliteration 4
    squarediagonaliteration 5
    squarediagonaliteration 6
    squarediagonaliteration 7
    squarediagonaliteration 8
    squarediagonaliteration 9
    squarediagonaliteration 10
    squarediagonaliteration 11
.endm

@ r0 is a pointer to the BigInt<768> to store the final result
@ r1 is a pointer to the BigInt<384> to square
embedded_pairing_core_arch_armv6_m_bigint_768_square:
    push {r4, r5, r6, r7}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4, r5, r6, r7}

    @ Store these so we can recover them
    mov r8, r0
    mov r9, r1

    @ Allocate space for temporary BigInt<768> "tmp" storing the product
    sub sp, sp, #96

    square768part1
    square768part2
    mov r1, r9
    square768part3

    @ Copy result into final BigInt<768> variable
    mov r0, r8
    mov r1, sp
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}

    @ Deallocate space for temporary BigInt<768> "tmp"
    add sp, sp, #96

    pop {r4, r5, r6, r7}
    mov r11, r7
    mov r10, r6
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7}
    bx lr

.globl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_square
.type embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_square, %function
.text
.thumb

@ r0 contains a pointer to the MontgomeryFpBase where to store the final result
@ r1 contains a pointer to operand "a"
@ r2 contains a pointer to the modulus "p"
@ r3 contains the "inv" value for Montgomery Reduction
embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_square:
    @ Save registers
    push {r4, r5, r6, r7, lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4, r5, r6, r7}

    @ Store p in r8, until we need it for montgomery reduction
    mov r8, r2
    mov r9, r3
    mov r10, r1
    mov r11, r0

    @ Allocate space for temporary BigInt<768> "tmp" storing the product
    sub sp, sp, #96

    @ Compute the square a^2 and store it in tmp

    square768part1
    square768part2
    mov r1, r10
    square768part3

    @ Perform Montgomery Reduction on tmp
    mov r1, r8 @ We bring p to r1; now r8 is used for the meta-carry

    mov r2, r9
    montgomeryreduce384

    @ Final step of Montgomery Reduction
    mov r0, r11
    mov r2, r1
    add r1, sp, #48
    bl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_reduce

    @ Deallocate space for temporary BigInt<768> "tmp"
    add sp, sp, #96

    @ Restore registers
    pop {r4, r5, r6, r7}
    mov r11, r7
    mov r10, r6
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7, pc}

.globl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_montgomery_reduce
.type embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_montgomery_reduce, %function
.text
.thumb

@ r0 has a pointer to the "this", the target where to store the result
@ r1 has a pointer to the BigInt<768> to reduce
@ r2 contains a pointer to the modulus "p"
@ r3 contains the "inv" value for Montgomery Reduction
embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_montgomery_reduce:
    @ Save registers
    push {r4, r5, r6, r7, lr}
    mov r4, r8
    mov r5, r9
    mov r6, r10
    mov r7, r11
    push {r4, r5, r6, r7}

    mov r8, r2
    mov r9, r3
    mov r11, r0

    @ Allocate space for temporary BigInt<768> "tmp" storing the product
    sub sp, sp, #96

    mov r0, sp
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}
    ldm r1!, {r2-r7}
    stm r0!, {r2-r7}

    @ Perform Montgomery Reduction on tmp
    mov r1, r8 @ We bring p to r1; now r8 is used for the meta-carry

    mov r2, r9
    montgomeryreduce384

    @ Final step of Montgomery Reduction
    mov r0, r11
    mov r2, r1
    add r1, sp, #48
    bl embedded_pairing_core_arch_armv6_m_montgomeryfpbase_384_reduce

    @ Deallocate space for temporary BigInt<768> "tmp"
    add sp, sp, #96

    @ Restore registers
    pop {r4, r5, r6, r7}
    mov r11, r7
    mov r10, r6
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7, pc}
