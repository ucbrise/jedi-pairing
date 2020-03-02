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

#include <stdint.h>
#include "bls12_381/fq.hpp"
#include "bls12_381/fq2.hpp"
#include "bls12_381/curve.hpp"
#include "bls12_381/decomposition.hpp"

namespace embedded_pairing::bls12_381 {
    extern constexpr Fq g1_b_coeff_var = g1_b_coeff;
    extern constexpr Fq2 g2_b_coeff_var = g2_b_coeff;

    template <typename Projective, typename Affine, typename BaseField>
    void sample_random_generator(Projective& result, void (*get_random_bytes)(void*, size_t)) {
        do {
            Affine random;
            BaseField x;
            unsigned char b;

            do {
                x.random(get_random_bytes);
                get_random_bytes(&b, sizeof(b));
            } while (!random.get_point_from_x(x, (b & 0x1) == 0x1, true));

            result.multiply(random, Affine::cofactor);
        } while (result.is_zero());
    }

    void G1::random_generator(void (*get_random_bytes)(void*, size_t)) {
        sample_random_generator<G1, G1Affine, Fq>(*this, get_random_bytes);
    }

    void G2::random_generator(void (*get_random_bytes)(void*, size_t)) {
        sample_random_generator<G2, G2Affine, Fq2>(*this, get_random_bytes);
    }

    /* Procedures for encoding/decoding. */

    template <typename Affine, bool compressed>
    void Encoding<Affine, compressed>::encode(const Affine& g) {
        if (g.is_zero()) {
            memset(this->data, 0x0, sizeof(this->data));
            this->data[0] = encoding_flags_infinity;
        } else {
            g.x.write_big_endian(&this->data[0]);

            if constexpr(compressed) {
                typename Affine::BaseFieldType negy;
                negy.negate(g.y);

                if (Affine::BaseFieldType::compare(g.y, negy) == 1) {
                    this->data[0] |= encoding_flags_greater;
                }
            } else {
                g.y.write_big_endian(&this->data[sizeof(typename Affine::BaseFieldType)]);
            }
        }
        if constexpr(compressed) {
            this->data[0] |= encoding_flags_compressed;
        }
    }

    template <typename Affine, bool compressed>
    bool Encoding<Affine, compressed>::decode(Affine& g, bool checked) const {
        if (checked && is_encoding_compressed(this->data[0]) != compressed) {
            return false;
        }
        if ((this->data[0] & encoding_flags_infinity) != 0) {
            if (checked) {
                if ((this->data[0] & ~(encoding_flags_compressed | encoding_flags_infinity)) != 0) {
                    return false;
                }
                for (int i = 1; i != sizeof(this->data); i++) {
                    if (this->data[i] != 0) {
                        return false;
                    }
                }
            }
            g.copy(Affine::zero);
            return true;
        }

        /* The "read_big_endian" method masks off the three control bits. */
        g.x.read_big_endian(&this->data[0]);

        bool greater = ((this->data[0] & encoding_flags_greater) != 0);
        if constexpr(compressed) {
            if (!g.get_point_from_x(g.x, greater, checked)) {
                return false;
            }
        } else {
            if (checked && greater) {
                return false;
            }
            g.y.read_big_endian(&this->data[sizeof(typename Affine::BaseFieldType)]);
            g.infinity = false;
        }

        if (checked) {
            if constexpr(!compressed) {
                if (!g.is_on_curve()) {
                    return false;
                }
            }
            return g.is_in_correct_subgroup_assuming_on_curve();
        }

        return true;
    }

    /* Explicitly instantiate Encoding templates. */
    template struct Encoding<G1Affine, false>;
    template struct Encoding<G1Affine, true>;
    template struct Encoding<G2Affine, false>;
    template struct Encoding<G2Affine, true>;
}
