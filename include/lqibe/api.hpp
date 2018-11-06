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

#ifndef EMBEDDED_PAIRING_LQIBE_API_HPP_
#define EMBEDDED_PAIRING_LQIBE_API_HPP_

#include <stdint.h>

#include "core/bigint.hpp"
#include "bls12_381/fr.hpp"
#include "bls12_381/fq12.hpp"
#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"

namespace embedded_pairing::lqibe {
    typedef bls12_381::G1 G1;
    typedef bls12_381::G2 G2;
    typedef bls12_381::G1Affine G1Affine;
    typedef bls12_381::G2Affine G2Affine;
    typedef bls12_381::Fq12 GT;
    typedef core::BigInt<256> Scalar;

    const core::BigInt<256> group_order = bls12_381::Fr::p_value;

    struct IDHash {
        uint8_t hash[sizeof(G2::BaseFieldType)];
    };

    struct Params {
        G1 p;
        G1 sp;

        template <bool compressed>
        void marshal(void* buffer) const;

        template <bool compressed>
        bool unmarshal(const void* buffer, bool checked);

        template <bool compressed>
        static constexpr size_t marshalledLength = 2 * bls12_381::Encoding<G1Affine, compressed>::size;
    };

    struct ID {
        G2 q;

        template <bool compressed>
        void marshal(void* buffer) const;

        template <bool compressed>
        bool unmarshal(const void* buffer, bool checked);

        template <bool compressed>
        static constexpr size_t marshalledLength = bls12_381::Encoding<G1Affine, compressed>::size;
    };

    struct MasterKey {
        Scalar s;

        template <bool compressed>
        void marshal(void* buffer) const {
            memcpy(buffer, &this->s, sizeof(Scalar));
        }

        template <bool compressed>
        bool unmarshal(const void* buffer, bool checked) {
            memcpy(&this->s, buffer, sizeof(Scalar));
            return true;
        }

        template <bool compressed>
        static constexpr size_t marshalledLength = sizeof(Scalar);
    };

    struct SecretKey {
        G2Affine sq;

        template <bool compressed>
        void marshal(void* buffer) const;

        template <bool compressed>
        bool unmarshal(const void* buffer, bool checked);

        template <bool compressed>
        static constexpr size_t marshalledLength = bls12_381::Encoding<G2Affine, compressed>::size;
    };

    struct Ciphertext {
        G1 rp;

        template <bool compressed>
        void marshal(void* buffer) const;

        template <bool compressed>
        bool unmarshal(const void* buffer, bool checked);

        template <bool compressed>
        static constexpr size_t marshalledLength = bls12_381::Encoding<G1Affine, compressed>::size;
    };

    void compute_id_from_hash(ID& id, const IDHash& hash);

    void setup(Params& params, MasterKey& msk, void (*get_random_bytes)(void*, size_t));
    void keygen(SecretKey& sk, const MasterKey& msk, const ID& id);
    void encrypt(Ciphertext& ciphertext, void* symmetric, size_t symmetric_length, const Params& params, const ID& id, void (*hash_fill)(void*, size_t, const void*, size_t), void (*get_random_bytes)(void*, size_t));
    void decrypt(void* symmetric, size_t symmetric_length, const Ciphertext& ciphertext, const SecretKey& sk, const ID& id, void (*hash_fill)(void*, size_t, const void*, size_t));
}

#endif
