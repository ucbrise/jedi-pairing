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

#include "wkdibe/api.hpp"

#include <stdint.h>

#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"

using embedded_pairing::bls12_381::Encoding;

namespace embedded_pairing::wkdibe {
    /* We need this because #include <endian.h> is not portable. */
    static inline uint32_t uint32_swap_endianness(uint32_t x) {
        uint32_t temp = (x << 16) | (x >> 16);
        return ((temp & 0x00FF00FFu) << 8) | ((temp & 0xFF00FF00u) >> 8);
    }

    template <bool compressed>
    struct ParamsMarshalled {
        uint8_t signature;
        Encoding<G2Affine, compressed> g;
        Encoding<G2Affine, compressed> g1;
        Encoding<G1Affine, compressed> g2;
        Encoding<G1Affine, compressed> g3;
        uint8_t pairing[compressed ? 0 : sizeof(GT)];
    };

    template <bool compressed>
    void Params::marshal(void* buffer) const {
        ParamsMarshalled<compressed>* encoded = static_cast<ParamsMarshalled<compressed>*>(buffer);
        encoded->signature = this->signatures ? 1 : 0;

        G2Affine gaffine;
        gaffine.from_projective(this->g);
        encoded->g.encode(gaffine);

        G2Affine g1affine;
        g1affine.from_projective(this->g1);
        encoded->g1.encode(g1affine);

        G1Affine g2affine;
        g2affine.from_projective(this->g2);
        encoded->g2.encode(g2affine);

        G1Affine g3affine;
        g3affine.from_projective(this->g3);
        encoded->g3.encode(g3affine);

        if constexpr(!compressed) {
            memcpy(encoded->pairing, &this->pairing, sizeof(GT));
        }

        Encoding<G1Affine, compressed>* h;
        if (this->signatures) {
            Encoding<G1Affine, compressed>* hsig = reinterpret_cast<Encoding<G1Affine, compressed>*>(encoded + 1);

            G1Affine hsigaffine;
            hsigaffine.from_projective(this->hsig);
            hsig->encode(hsigaffine);

            h = hsig + 1;
        } else {
            h = reinterpret_cast<Encoding<G1Affine, compressed>*>(encoded + 1);
        }

        for (int i = 0; i != this->l; i++) {
            G1Affine haffine;
            haffine.from_projective(this->h[i]);
            h[i].encode(haffine);
        }
    }

    template <bool compressed>
    bool Params::unmarshal(const void* buffer, bool checked) {
        const ParamsMarshalled<compressed>* encoded = static_cast<const ParamsMarshalled<compressed>*>(buffer);
        this->signatures = (encoded->signature != 0);

        G2Affine gaffine;
        if (!encoded->g.decode(gaffine, checked)) {
            return false;
        }
        this->g.from_affine(gaffine);

        G2Affine g1affine;
        if (!encoded->g1.decode(g1affine, checked)) {
            return false;
        }
        this->g1.from_affine(g1affine);

        G1Affine g2affine;
        if (!encoded->g2.decode(g2affine, checked)) {
            return false;
        }
        this->g2.from_affine(g2affine);

        G1Affine g3affine;
        if (!encoded->g3.decode(g3affine, checked)) {
            return false;
        }
        this->g3.from_affine(g3affine);

        if constexpr(compressed) {
            bls12_381::pairing(this->pairing, g2affine, g1affine);
        } else {
            memcpy(&this->pairing, encoded->pairing, sizeof(GT));
        }

        const Encoding<G1Affine, compressed>* h;
        if (this->signatures) {
            const Encoding<G1Affine, compressed>* hsig = reinterpret_cast<const Encoding<G1Affine, compressed>*>(encoded + 1);

            G1Affine hsigaffine;
            if (!hsig->decode(hsigaffine, checked)) {
                return false;
            }
            this->hsig.from_affine(hsigaffine);

            h = hsig + 1;
        } else {
            h = reinterpret_cast<const Encoding<G1Affine, compressed>*>(encoded + 1);
        }

        for (int i = 0; i != this->l; i++) {
            G1Affine haffine;
            if (!h[i].decode(haffine, checked)) {
                return false;
            }
            this->h[i].from_affine(haffine);
        }

        return true;
    }

    template <bool compressed>
    struct CiphertextMarshalled {
        uint8_t a[sizeof(GT)];
        Encoding<G2Affine, compressed> b;
        Encoding<G1Affine, compressed> c;
    };

    template <bool compressed>
    void Ciphertext::marshal(void* buffer) const {
        CiphertextMarshalled<compressed>* encoded = static_cast<CiphertextMarshalled<compressed>*>(buffer);
        memcpy(encoded->a, &this->a, sizeof(GT));

        G2Affine baffine;
        baffine.from_projective(this->b);
        encoded->b.encode(baffine);

        G1Affine caffine;
        caffine.from_projective(this->c);
        encoded->c.encode(caffine);
    }

    template <bool compressed>
    bool Ciphertext::unmarshal(const void* buffer, bool checked) {
        const CiphertextMarshalled<compressed>* encoded = reinterpret_cast<const CiphertextMarshalled<compressed>*>(buffer);
        memcpy(&this->a, encoded->a, sizeof(GT));

        G2Affine baffine;
        if (!encoded->b.decode(baffine, checked)) {
            return false;
        }
        this->b.from_affine(baffine);

        G1Affine caffine;
        if (!encoded->c.decode(caffine, checked)) {
            return false;
        }
        this->c.from_affine(caffine);

        return true;
    }

    template <bool compressed>
    struct SignatureMarshalled {
        Encoding<G1Affine, compressed> a0;
        Encoding<G2Affine, compressed> a1;
    };

    template <bool compressed>
    void Signature::marshal(void* buffer) const {
        SignatureMarshalled<compressed>* encoded = static_cast<SignatureMarshalled<compressed>*>(buffer);

        G1Affine a0affine;
        a0affine.from_projective(this->a0);
        encoded->a0.encode(a0affine);

        G2Affine a1affine;
        a1affine.from_projective(this->a1);
        encoded->a1.encode(a1affine);
    }

    template <bool compressed>
    bool Signature::unmarshal(const void* buffer, bool checked) {
        const SignatureMarshalled<compressed>* encoded = static_cast<const SignatureMarshalled<compressed>*>(buffer);

        G1Affine a0affine;
        if (!encoded->a0.decode(a0affine, checked)) {
            return false;
        }
        this->a0.from_affine(a0affine);

        G2Affine a1affine;
        if (!encoded->a1.decode(a1affine, checked)) {
            return false;
        }
        this->a1.from_affine(a1affine);

        return true;
    }

    template <bool compressed>
    struct FreeSlotMarshalled {
        Encoding<G1Affine, compressed> hexp;
        uint32_t idx;
    };

    template <bool compressed>
    void FreeSlot::marshal(void* buffer) const {
        FreeSlotMarshalled<compressed>* encoded = static_cast<FreeSlotMarshalled<compressed>*>(buffer);

        G1Affine hexpaffine;
        hexpaffine.from_projective(this->hexp);
        encoded->hexp.encode(hexpaffine);

        encoded->idx = uint32_swap_endianness(this->idx);
    }

    template <bool compressed>
    bool FreeSlot::unmarshal(const void* buffer, bool checked) {
        const FreeSlotMarshalled<compressed>* encoded = static_cast<const FreeSlotMarshalled<compressed>*>(buffer);

        G1Affine hexpaffine;
        if (!encoded->hexp.decode(hexpaffine, checked)) {
            return false;
        }
        this->hexp.from_affine(hexpaffine);

        this->idx = uint32_swap_endianness(encoded->idx);
        return true;
    }

    template <bool compressed>
    struct SecretKeyMarshalled {
        uint8_t signature;
        Encoding<G1Affine, compressed> a0;
        Encoding<G2Affine, compressed> a1;
    };

    template <bool compressed>
    void SecretKey::marshal(void* buffer) const {
        SecretKeyMarshalled<compressed>* encoded = static_cast<SecretKeyMarshalled<compressed>*>(buffer);
        encoded->signature = this->signatures ? 1 : 0;

        G1Affine a0affine;
        a0affine.from_projective(this->a0);
        encoded->a0.encode(a0affine);

        G2Affine a1affine;
        a1affine.from_projective(this->a1);
        encoded->a1.encode(a1affine);

        FreeSlotMarshalled<compressed>* b;
        if (this->signatures) {
            Encoding<G1Affine, compressed>* bsig = reinterpret_cast<Encoding<G1Affine, compressed>*>(encoded + 1);

            G1Affine bsigaffine;
            bsigaffine.from_projective(this->bsig);
            bsig->encode(bsigaffine);

            b = reinterpret_cast<FreeSlotMarshalled<compressed>*>(bsig + 1);
        } else {
            b = reinterpret_cast<FreeSlotMarshalled<compressed>*>(encoded + 1);
        }

        for (int i = 0; i != this->l; i++) {
            this->b[i].marshal<compressed>(&b[i]);
        }
    }

    template <bool compressed>
    bool SecretKey::unmarshal(const void* buffer, bool checked) {
        const SecretKeyMarshalled<compressed>* encoded = static_cast<const SecretKeyMarshalled<compressed>*>(buffer);
        this->signatures = (encoded->signature != 0);

        G1Affine a0affine;
        if (!encoded->a0.decode(a0affine, checked)) {
            return false;
        }
        this->a0.from_affine(a0affine);

        G2Affine a1affine;
        if (!encoded->a1.decode(a1affine, checked)) {
            return false;
        }
        this->a1.from_affine(a1affine);

        const FreeSlotMarshalled<compressed>* b;
        if (this->signatures) {
            const Encoding<G1Affine, compressed>* bsig = reinterpret_cast<const Encoding<G1Affine, compressed>*>(encoded + 1);

            G1Affine bsigaffine;
            if (!bsig->decode(bsigaffine, checked)) {
                return false;
            }
            this->bsig.from_affine(bsigaffine);

            b = reinterpret_cast<const FreeSlotMarshalled<compressed>*>(bsig + 1);
        } else {
            b = reinterpret_cast<const FreeSlotMarshalled<compressed>*>(encoded + 1);
        }

        for (int i = 0; i != this->l; i++) {
            if (!this->b[i].unmarshal<compressed>(&b[i], checked)) {
                return false;
            }
        }

        return true;
    }

    template <bool compressed>
    void MasterKey::marshal(void* buffer) const {
        Encoding<G1Affine, compressed>* encoded = static_cast<Encoding<G1Affine, compressed>*>(buffer);

        G1Affine g2alphaaffine;
        g2alphaaffine.from_projective(this->g2alpha);
        encoded->encode(g2alphaaffine);
    }

    template <bool compressed>
    bool MasterKey::unmarshal(const void* buffer, bool checked) {
        const Encoding<G1Affine, compressed>* encoded = static_cast<const Encoding<G1Affine, compressed>*>(buffer);

        G1Affine g2alphaaffine;
        if (!encoded->decode(g2alphaaffine, checked)) {
            return false;
        }
        this->g2alpha.from_affine(g2alphaaffine);

        return true;
    }

    /* Explicitly instantiate the function templates. */
    template void Params::marshal<false>(void*) const;
    template void Params::marshal<true>(void*) const;
    template bool Params::unmarshal<false>(const void*, bool);
    template bool Params::unmarshal<true>(const void*, bool);
    template void Ciphertext::marshal<false>(void*) const;
    template void Ciphertext::marshal<true>(void*) const;
    template bool Ciphertext::unmarshal<false>(const void*, bool);
    template bool Ciphertext::unmarshal<true>(const void*, bool);
    template void Signature::marshal<false>(void*) const;
    template void Signature::marshal<true>(void*) const;
    template bool Signature::unmarshal<false>(const void*, bool);
    template bool Signature::unmarshal<true>(const void*, bool);
    template void SecretKey::marshal<false>(void*) const;
    template void SecretKey::marshal<true>(void*) const;
    template bool SecretKey::unmarshal<false>(const void*, bool);
    template bool SecretKey::unmarshal<true>(const void*, bool);
    template void MasterKey::marshal<false>(void*) const;
    template void MasterKey::marshal<true>(void*) const;
    template bool MasterKey::unmarshal<false>(const void*, bool);
    template bool MasterKey::unmarshal<true>(const void*, bool);
}
