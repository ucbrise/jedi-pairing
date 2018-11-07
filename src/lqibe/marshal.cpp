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

#include "lqibe/api.hpp"

#include "bls12_381/curve.hpp"

namespace embedded_pairing::lqibe {
    template <bool compressed>
    struct ParamsMarshalled {
        bls12_381::Encoding<G2Affine, compressed> p;
        bls12_381::Encoding<G2Affine, compressed> sp;
    };

    template <bool compressed>
    void Params::marshal(void* buffer) const {
        ParamsMarshalled<compressed>* encoded = reinterpret_cast<ParamsMarshalled<compressed>*>(buffer);

        G2Affine paffine;
        paffine.from_projective(this->p);
        encoded->p.encode(paffine);

        G2Affine spaffine;
        spaffine.from_projective(this->sp);
        encoded->sp.encode(spaffine);
    }

    template <bool compressed>
    bool Params::unmarshal(const void* buffer, bool checked) {
        const ParamsMarshalled<compressed>* encoded = reinterpret_cast<const ParamsMarshalled<compressed>*>(buffer);

        G2Affine paffine;
        if (!encoded->p.decode(paffine, checked)) {
            return false;
        }
        this->p.from_affine(paffine);

        G2Affine spaffine;
        if (!encoded->sp.decode(spaffine, checked)) {
            return false;
        }
        this->sp.from_affine(spaffine);

        return true;
    }

    template <bool compressed>
    void ID::marshal(void* buffer) const {
        bls12_381::Encoding<G1Affine, compressed>* encoded = reinterpret_cast<bls12_381::Encoding<G1Affine, compressed>*>(buffer);
        encoded->encode(this->q);
    }

    template <bool compressed>
    bool ID::unmarshal(const void* buffer, bool checked) {
        const bls12_381::Encoding<G1Affine, compressed>* encoded = reinterpret_cast<const bls12_381::Encoding<G1Affine, compressed>*>(buffer);
        return encoded->decode(this->q, checked);
    }

    template <bool compressed>
    void SecretKey::marshal(void* buffer) const {
        bls12_381::Encoding<G1Affine, compressed>* encoded = reinterpret_cast<bls12_381::Encoding<G1Affine, compressed>*>(buffer);
        encoded->encode(this->sq);
    }

    template <bool compressed>
    bool SecretKey::unmarshal(const void* buffer, bool checked) {
        const bls12_381::Encoding<G1Affine, compressed>* encoded = reinterpret_cast<const bls12_381::Encoding<G1Affine, compressed>*>(buffer);
        return encoded->decode(this->sq, checked);
    }

    template <bool compressed>
    void Ciphertext::marshal(void* buffer) const {
        bls12_381::Encoding<G2Affine, compressed>* encoded = reinterpret_cast<bls12_381::Encoding<G2Affine, compressed>*>(buffer);
        encoded->encode(this->rp);
    }

    template <bool compressed>
    bool Ciphertext::unmarshal(const void* buffer, bool checked) {
        const bls12_381::Encoding<G2Affine, compressed>* encoded = reinterpret_cast<const bls12_381::Encoding<G2Affine, compressed>*>(buffer);
        return encoded->decode(this->rp, checked);
    }

    /* Explicitly instantiate the function templates. */
    template void Params::marshal<false>(void*) const;
    template void Params::marshal<true>(void*) const;
    template bool Params::unmarshal<false>(const void*, bool);
    template bool Params::unmarshal<true>(const void*, bool);
    template void ID::marshal<false>(void*) const;
    template void ID::marshal<true>(void*) const;
    template bool ID::unmarshal<false>(const void*, bool);
    template bool ID::unmarshal<true>(const void*, bool);
    template void SecretKey::marshal<false>(void*) const;
    template void SecretKey::marshal<true>(void*) const;
    template bool SecretKey::unmarshal<false>(const void*, bool);
    template bool SecretKey::unmarshal<true>(const void*, bool);
    template void Ciphertext::marshal<false>(void*) const;
    template void Ciphertext::marshal<true>(void*) const;
    template bool Ciphertext::unmarshal<false>(const void*, bool);
    template bool Ciphertext::unmarshal<true>(const void*, bool);
}
