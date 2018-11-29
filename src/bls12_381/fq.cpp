/*
 * Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2018, University of California, Berkeley
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "core/bigint.hpp"
#include "core/fp.hpp"
#include "core/fp_utils.hpp"
#include "bls12_381/fq.hpp"

#include <stddef.h>

namespace embedded_pairing::bls12_381 {
    /* Constants for instantiating the Fp class template for Fq. */
    extern constexpr BigInt<fq_bits> fq_modulus_var = fq_modulus;
    extern constexpr BigInt<fq_bits> fq_R_var = fq_R;
    extern constexpr BigInt<fq_bits> fq_R2_var = fq_R2;
    extern constexpr BigInt<fq_bits> fq_inv_var = fq_inv;

    /* The constant ((q - 3) // 4) + 1, used for computing the square root. */
    static constexpr BigInt<fq_bits> fq_qminusthreeoverfourplusone = {.std_words = { 0xffffeaab, 0xee7fbfff, 0xac54ffff, 0x7aaffff, 0x3dac3d89, 0xd9cc34a8, 0x3ce144af, 0xd91dd2e1, 0x90d2eb35, 0x92c6e9ed, 0x8e5ff9a6, 0x680447a }};

    void Fq::square_root(const Fq& a) {
        exponentiate(*this, a, fq_qminusthreeoverfourplusone);
    }

    void Fq::random(void (*get_random_bytes)(void*, size_t)) {
        do {
            get_random_bytes(this->val.bytes, sizeof(this->val.bytes));
            // Discard the top three bits, as the prime modulus is 0 in those bits
            this->val.bytes[BigInt<fq_bits>::byte_length - 1] &= 0x1F;
        } while (BigInt<fq_bits>::compare(this->val, fq_modulus) >= 0);
    }

    bool Fq::hash_reduce() {
        // Discard the top three bits, as the prime modulus is 0 in those bits
        uint8_t& top_byte = this->val.bytes[BigInt<fq_bits>::byte_length - 1];
        bool top_bit = (top_byte >> 7) != 0;
        top_byte &= 0x1F;

        if (BigInt<fq_bits>::compare(this->val, fq_modulus) == -1) {
#ifdef RESIST_SIDE_CHANNELS
            this->val.subtract(this->val, BigInt<bits>::zero);
#endif
        } else {
            this->val.subtract(this->val, fq_modulus);
        }

        return top_bit;
    }

    void Fq::write_big_endian(uint8_t* buffer) const {
        BigInt<fq_bits> temp;
        this->get(temp);
        temp.write_big_endian(buffer);
    }

    void Fq::read_big_endian(const uint8_t* buffer) {
        this->val.read_big_endian(buffer);
        this->val.bytes[BigInt<fq_bits>::byte_length - 1] &= 0x1F;
        this->into_montgomery_form();
    }
}
