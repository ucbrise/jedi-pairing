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

.globl embedded_pairing_core_arch_thumb_bigint_384_add
.type embedded_pairing_core_arch_thumb_bigint_384_add, %function
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
embedded_pairing_core_arch_thumb_bigint_384_add:
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


.globl embedded_pairing_core_arch_thumb_bigint_768_multiply
.type embedded_pairing_core_arch_thumb_bigint_768_muliply, %function
.text
.thumb

@ The biggest challenge with multiply is that we only get the lower half of the
@ product. Computing the upper half depends on carry bits from computing the
@ lower half, which we don't have. So we (unfortunately) have to redo some of
@ that computation to recover the carry bits.

@ The macro multiply32 computes the product of two numbers stored in memory,
@ storing the output carry in r3. It is split in three parts so that additional
@ additions (e.g., input carry, multiply-add support) can be handled in
@ between parts.

.macro multiply32part1 src1_off, src2_off
    uxth r5, r4 @ lower half of a, denoted a0
    uxth r6, r3 @ lower half of b, denoted b0
    lsr r4, r4, #16 @ upper half of a, denoted a1
    lsr r3, r3, #16 @ upper half of b, denoted b1
    mov r7, r6

    mul r6, r5, r6 @ a0 * b0
    mul r5, r5, r3 @ a0 * b1
    mul r3, r3, r4 @ a1 * b1
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

@ The fact that part 3 starts with adc instead of add allows it to provide a
@ "free" carry for computation between parts 2 and 3, where it would normally
@ cost an extra cycle.

.macro multiply32part3 dst_off
    @ Add carry from (r4 + r5) to top half of top result (r3)
    @ Using adc provides a "free" carry for code between the two halves
    adc r3, r3, r5

    @ Split the sum (r4 + r5) into top half of bottom and bottom half of top
    lsl r5, r4, #16
    lsr r4, r4, #16
    add r6, r6, r5
    adc r3, r3, r4

    @ Store result (output carry remains in r3)
    str r6, [r0, #\dst_off]
.endm

.macro multiply32 dst_off, src1_off, src2_off
    multiply32part1 \src1_off, \src2_off
    multiply32part2
    multiply32part3 \dst_off
.endm

@ Same as multiply32, except that it receives an input carry in r8.
.macro mulcarry32 dst_off, src1_off, src2_off
    multiply32part1 \src1_off, \src2_off
    multiply32part2

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    @ The multiply32secondhalf macro begins with adc and does the carry to r3
    mov r7, r8
    add r6, r6, r7

    multiply32part3 \dst_off
.endm

@ The macro muladd32 multiplies words at the specified offets from r1 and r2,
@ adds it to the word at the specified offset from r0, and stores the result
@ at that same offset.
.macro muladd32 dst_off, src1_off, src2_off
    multiply32part1 \src1_off, \src2_off
    multiply32part2

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    @ The multiply32secondhalf macro begins with adc and does the carry to r3
    ldr r7, [r0, #\dst_off]
    add r6, r6, r7

    multiply32part3 \dst_off
.endm

@ The macro muladdcarry32 is the same as muladd32, except that it also accepts
@ an input carry, added to the result, in the register r8.
.macro muladdcarry32 dst_off, src1_off, src2_off
    multiply32part1 \src1_off, \src2_off

    @ Handle the input carry. The carry after adding to the lower result is
    @ handled by adding it to r5, which is anyway going to be added to \a. The
    @ advantage to doing this is that we don't need to spend a cycle obtaining
    @ a zero register to extract the carry bit. Basically, we customize
    @ multiply32part2 to save this cycle.
    lsl r5, r5, #15 @ Note we only shift left by 15 bits; this will be doubled
    mov r7, r8
    add r6, r6, r7 @ add r6, r6, r8 won't update the carry flag, hence the mov
    adc r5, r5, r5 @ We double r5 and add the carry bit

    @ Add existing word to bottom result (r6), carrying to top result (r3)
    ldr r7, [r0, #\dst_off]
    add r6, r6, r7

    multiply32part3 \dst_off
.endm

.macro multiplyloopiteration i
    ldr r4, [r1, #4*\i]
    mov r9, r4
    ldr r3, [r2, #0]
    muladd32 4*\i, 4*\i, 0
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #4]
    muladdcarry32 4*\i+4, 4*\i, 4
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #8]
    muladdcarry32 4*\i+8, 4*\i, 8
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #12]
    muladdcarry32 4*\i+12, 4*\i, 12
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #16]
    muladdcarry32 4*\i+16, 4*\i, 16
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #20]
    muladdcarry32 4*\i+20, 4*\i, 20
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #24]
    muladdcarry32 4*\i+24, 4*\i, 24
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #28]
    muladdcarry32 4*\i+28, 4*\i, 28
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #32]
    muladdcarry32 4*\i+32, 4*\i, 32
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #36]
    muladdcarry32 4*\i+36, 4*\i, 36
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #40]
    muladdcarry32 4*\i+40, 4*\i, 40
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #44]
    muladdcarry32 4*\i+44, 4*\i, 44
    str r3, [r0, #4*\i+48]
.endm

@ r0 contains a pointer to the BigInt where the result should be stored
@ r1 contains a pointer to operand "a"
@ r2 contains a pointer to operand "b"
embedded_pairing_core_arch_thumb_bigint_768_multiply:
    @ Save registers
    push {r4, r5, r6, r7}
    mov r4, r8
    mov r5, r9
    push {r4, r5}

    @ Iteration: i = 0
    ldr r4, [r1, #0]
    mov r9, r4
    ldr r3, [r2, #0]
    multiply32 0
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #4]
    mulcarry32 4
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #8]
    mulcarry32 8
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #12]
    mulcarry32 12
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #16]
    mulcarry32 16
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #20]
    mulcarry32 20
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #24]
    mulcarry32 24
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #28]
    mulcarry32 28
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #32]
    mulcarry32 32
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #36]
    mulcarry32 36
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #40]
    mulcarry32 40
    mov r8, r3

    mov r4, r9
    ldr r3, [r2, #44]
    mulcarry32 44
    str r3, [r0, #48]

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

    @ Restore registers
    pop {r4, r5}
    mov r9, r5
    mov r8, r4
    pop {r4, r5, r6, r7}
    bx lr
