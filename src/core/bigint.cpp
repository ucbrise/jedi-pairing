#include "core/bigint.hpp"

namespace embedded_pairing::core {
    /* Candidate optimizations... */

// #if defined(__SIZEOF_INT128__)
//     template <>
//     void BigInt<768>::multiply(const BigInt<384>& __restrict a, const BigInt<384>& __restrict b) {
//         word_t carry = 0;
//         word_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11;
//
//         r0 = mac_with_carry(0, a.words[0], b.words[0], &carry);
//         r1 = mac_with_carry(0, a.words[0], b.words[1], &carry);
//         r2 = mac_with_carry(0, a.words[0], b.words[2], &carry);
//         r3 = mac_with_carry(0, a.words[0], b.words[3], &carry);
//         r4 = mac_with_carry(0, a.words[0], b.words[4], &carry);
//         r5 = mac_with_carry(0, a.words[0], b.words[5], &carry);
//         r6 = carry;
//
//         carry = 0;
//         r1 = mac_with_carry(r1, a.words[1], b.words[0], &carry);
//         r2 = mac_with_carry(r2, a.words[1], b.words[1], &carry);
//         r3 = mac_with_carry(r3, a.words[1], b.words[2], &carry);
//         r4 = mac_with_carry(r4, a.words[1], b.words[3], &carry);
//         r5 = mac_with_carry(r5, a.words[1], b.words[4], &carry);
//         r6 = mac_with_carry(r6, a.words[1], b.words[5], &carry);
//         r7 = carry;
//
//         carry = 0;
//         r2 = mac_with_carry(r2, a.words[2], b.words[0], &carry);
//         r3 = mac_with_carry(r3, a.words[2], b.words[1], &carry);
//         r4 = mac_with_carry(r4, a.words[2], b.words[2], &carry);
//         r5 = mac_with_carry(r5, a.words[2], b.words[3], &carry);
//         r6 = mac_with_carry(r6, a.words[2], b.words[4], &carry);
//         r7 = mac_with_carry(r7, a.words[2], b.words[5], &carry);
//         r8 = carry;
//
//         carry = 0;
//         r3 = mac_with_carry(r3, a.words[3], b.words[0], &carry);
//         r4 = mac_with_carry(r4, a.words[3], b.words[1], &carry);
//         r5 = mac_with_carry(r5, a.words[3], b.words[2], &carry);
//         r6 = mac_with_carry(r6, a.words[3], b.words[3], &carry);
//         r7 = mac_with_carry(r7, a.words[3], b.words[4], &carry);
//         r8 = mac_with_carry(r8, a.words[3], b.words[5], &carry);
//         r9 = carry;
//
//         carry = 0;
//         r4 = mac_with_carry(r4, a.words[4], b.words[0], &carry);
//         r5 = mac_with_carry(r5, a.words[4], b.words[1], &carry);
//         r6 = mac_with_carry(r6, a.words[4], b.words[2], &carry);
//         r7 = mac_with_carry(r7, a.words[4], b.words[3], &carry);
//         r8 = mac_with_carry(r8, a.words[4], b.words[4], &carry);
//         r9 = mac_with_carry(r9, a.words[4], b.words[5], &carry);
//         r10 = carry;
//
//         carry = 0;
//         r5 = mac_with_carry(r5, a.words[5], b.words[0], &carry);
//         r6 = mac_with_carry(r6, a.words[5], b.words[1], &carry);
//         r7 = mac_with_carry(r7, a.words[5], b.words[2], &carry);
//         r8 = mac_with_carry(r8, a.words[5], b.words[3], &carry);
//         r9 = mac_with_carry(r9, a.words[5], b.words[4], &carry);
//         r10 = mac_with_carry(r10, a.words[5], b.words[5], &carry);
//         r11 = carry;
//
//         this->words[0] = r0;
//         this->words[1] = r1;
//         this->words[2] = r2;
//         this->words[3] = r3;
//         this->words[4] = r4;
//         this->words[5] = r5;
//         this->words[6] = r6;
//         this->words[7] = r7;
//         this->words[8] = r8;
//         this->words[9] = r9;
//         this->words[10] = r10;
//         this->words[11] = r11;
//     }
//
// #endif

// Drop in for montgomeryfp.hpp's multiply. Written exactly as the Rust code,
// but not as fast...
// static inline typename BigInt<bits>::word_t mac_with_carry(typename BigInt<bits>::word_t a, typename BigInt<bits>::word_t b, typename BigInt<bits>::word_t c, typename BigInt<bits>::word_t* carry) {
//     typename BigInt<bits>::dword_t new_word = ((typename BigInt<bits>::dword_t) b) * ((typename BigInt<bits>::dword_t) c) + a + *carry;
//     *carry = new_word >> (sizeof(typename BigInt<bits>::word_t) * 8);
//     return (typename BigInt<bits>::word_t) new_word;
// }
//
// static inline typename BigInt<bits>::word_t adc(typename BigInt<bits>::word_t a, typename BigInt<bits>::word_t b, typename BigInt<bits>::word_t* carry) {
//     typename BigInt<bits>::dword_t new_word = ((typename BigInt<bits>::dword_t) a) + ((typename BigInt<bits>::dword_t) b) + *carry;
//     *carry = new_word >> (sizeof(typename BigInt<bits>::word_t) * 8);
//     return (typename BigInt<bits>::word_t) new_word;
// }
//
// void __attribute__((noinline)) multiply(const MontgomeryFp<bits, p, r, r2, inv>& a, const MontgomeryFp<bits, p, r, r2, inv>& b) {
//     if constexpr(bits == 384) {
//         typename BigInt<bits>::word_t carry = 0;
//         typename BigInt<bits>::word_t r0, r1, t2, r3, r4, r5, r6, r7, r8, r9, r10, r11;
//
//         r0 = mac_with_carry(0, a.val.words[0], b.val.words[0], &carry);
//         r1 = mac_with_carry(0, a.val.words[0], b.val.words[1], &carry);
//         t2 = mac_with_carry(0, a.val.words[0], b.val.words[2], &carry);
//         r3 = mac_with_carry(0, a.val.words[0], b.val.words[3], &carry);
//         r4 = mac_with_carry(0, a.val.words[0], b.val.words[4], &carry);
//         r5 = mac_with_carry(0, a.val.words[0], b.val.words[5], &carry);
//         r6 = carry;
//
//         carry = 0;
//         r1 = mac_with_carry(r1, a.val.words[1], b.val.words[0], &carry);
//         t2 = mac_with_carry(t2, a.val.words[1], b.val.words[1], &carry);
//         r3 = mac_with_carry(r3, a.val.words[1], b.val.words[2], &carry);
//         r4 = mac_with_carry(r4, a.val.words[1], b.val.words[3], &carry);
//         r5 = mac_with_carry(r5, a.val.words[1], b.val.words[4], &carry);
//         r6 = mac_with_carry(r6, a.val.words[1], b.val.words[5], &carry);
//         r7 = carry;
//
//         carry = 0;
//         t2 = mac_with_carry(t2, a.val.words[2], b.val.words[0], &carry);
//         r3 = mac_with_carry(r3, a.val.words[2], b.val.words[1], &carry);
//         r4 = mac_with_carry(r4, a.val.words[2], b.val.words[2], &carry);
//         r5 = mac_with_carry(r5, a.val.words[2], b.val.words[3], &carry);
//         r6 = mac_with_carry(r6, a.val.words[2], b.val.words[4], &carry);
//         r7 = mac_with_carry(r7, a.val.words[2], b.val.words[5], &carry);
//         r8 = carry;
//
//         carry = 0;
//         r3 = mac_with_carry(r3, a.val.words[3], b.val.words[0], &carry);
//         r4 = mac_with_carry(r4, a.val.words[3], b.val.words[1], &carry);
//         r5 = mac_with_carry(r5, a.val.words[3], b.val.words[2], &carry);
//         r6 = mac_with_carry(r6, a.val.words[3], b.val.words[3], &carry);
//         r7 = mac_with_carry(r7, a.val.words[3], b.val.words[4], &carry);
//         r8 = mac_with_carry(r8, a.val.words[3], b.val.words[5], &carry);
//         r9 = carry;
//
//         carry = 0;
//         r4 = mac_with_carry(r4, a.val.words[4], b.val.words[0], &carry);
//         r5 = mac_with_carry(r5, a.val.words[4], b.val.words[1], &carry);
//         r6 = mac_with_carry(r6, a.val.words[4], b.val.words[2], &carry);
//         r7 = mac_with_carry(r7, a.val.words[4], b.val.words[3], &carry);
//         r8 = mac_with_carry(r8, a.val.words[4], b.val.words[4], &carry);
//         r9 = mac_with_carry(r9, a.val.words[4], b.val.words[5], &carry);
//         r10 = carry;
//
//         carry = 0;
//         r5 = mac_with_carry(r5, a.val.words[5], b.val.words[0], &carry);
//         r6 = mac_with_carry(r6, a.val.words[5], b.val.words[1], &carry);
//         r7 = mac_with_carry(r7, a.val.words[5], b.val.words[2], &carry);
//         r8 = mac_with_carry(r8, a.val.words[5], b.val.words[3], &carry);
//         r9 = mac_with_carry(r9, a.val.words[5], b.val.words[4], &carry);
//         r10 = mac_with_carry(r10, a.val.words[5], b.val.words[5], &carry);
//         r11 = carry;
//
//         typename BigInt<bits>::word_t carry2;
//         static const typename BigInt<bits>::word_t inv_word = inv.words[0];
//         typename BigInt<bits>::word_t k = r0 * inv_word;
//         carry = 0;
//         mac_with_carry(r0, k, p.words[0], &carry);
//         r1 = mac_with_carry(r1, k, p.words[1], &carry);
//         t2 = mac_with_carry(t2, k, p.words[2], &carry);
//         r3 = mac_with_carry(r3, k, p.words[3], &carry);
//         r4 = mac_with_carry(r4, k, p.words[4], &carry);
//         r5 = mac_with_carry(r5, k, p.words[5], &carry);
//         r6 = adc(r6, 0, &carry);
//         carry2 = carry;
//         k = r1 * inv_word;
//         carry = 0;
//         mac_with_carry(r1, k, p.words[0], &carry);
//         t2 = mac_with_carry(t2, k, p.words[1], &carry);
//         r3 = mac_with_carry(r3, k, p.words[2], &carry);
//         r4 = mac_with_carry(r4, k, p.words[3], &carry);
//         r5 = mac_with_carry(r5, k, p.words[4], &carry);
//         r6 = mac_with_carry(r6, k, p.words[5], &carry);
//         r7 = adc(r7, carry2, &carry);
//         carry2 = carry;
//         k = t2 * inv_word;
//         carry = 0;
//         mac_with_carry(t2, k, p.words[0], &carry);
//         r3 = mac_with_carry(r3, k, p.words[1], &carry);
//         r4 = mac_with_carry(r4, k, p.words[2], &carry);
//         r5 = mac_with_carry(r5, k, p.words[3], &carry);
//         r6 = mac_with_carry(r6, k, p.words[4], &carry);
//         r7 = mac_with_carry(r7, k, p.words[5], &carry);
//         r8 = adc(r8, carry2, &carry);
//         carry2 = carry;
//         k = r3 * inv_word;
//         carry = 0;
//         mac_with_carry(r3, k, p.words[0], &carry);
//         r4 = mac_with_carry(r4, k, p.words[1], &carry);
//         r5 = mac_with_carry(r5, k, p.words[2], &carry);
//         r6 = mac_with_carry(r6, k, p.words[3], &carry);
//         r7 = mac_with_carry(r7, k, p.words[4], &carry);
//         r8 = mac_with_carry(r8, k, p.words[5], &carry);
//         r9 = adc(r9, carry2, &carry);
//         carry2 = carry;
//         k = r4 * inv_word;
//         carry = 0;
//         mac_with_carry(r4, k, p.words[0], &carry);
//         r5 = mac_with_carry(r5, k, p.words[1], &carry);
//         r6 = mac_with_carry(r6, k, p.words[2], &carry);
//         r7 = mac_with_carry(r7, k, p.words[3], &carry);
//         r8 = mac_with_carry(r8, k, p.words[4], &carry);
//         r9 = mac_with_carry(r9, k, p.words[5], &carry);
//         r10 = adc(r10, carry2, &carry);
//         carry2 = carry;
//         k = r5 * inv_word;
//         carry = 0;
//         mac_with_carry(r5, k, p.words[0], &carry);
//         r6 = mac_with_carry(r6, k, p.words[1], &carry);
//         r7 = mac_with_carry(r7, k, p.words[2], &carry);
//         r8 = mac_with_carry(r8, k, p.words[3], &carry);
//         r9 = mac_with_carry(r9, k, p.words[4], &carry);
//         r10 = mac_with_carry(r10, k, p.words[5], &carry);
//         r11 = adc(r11, carry2, &carry);
//         this->val.words[0] = r6;
//         this->val.words[1] = r7;
//         this->val.words[2] = r8;
//         this->val.words[3] = r9;
//         this->val.words[4] = r10;
//         this->val.words[5] = r11;
//
//         if (BigInt<bits>::compare(this->val, p) != -1) {
//             this->val.subtract(this->val, p);
//         }
//     } else {
//         BigInt<2*bits> tmp;
//         tmp.multiply(a.val, b.val);
//         this->montgomery_reduce(tmp);
//     }
// }
}
