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

#include <string.h>
#include <stdint.h>

#include "bls12_381/fq.hpp"
#include "bls12_381/wnaf.hpp"

namespace embedded_pairing::lqibe {
    void compute_id_from_hash(ID& id, const IDHash& hash) {
        G1Affine qaffine;
        qaffine.from_hash(hash.hash);

        G1 q;
        q.multiply_wnaf(qaffine, G1Affine::cofactor);

        id.q.from_projective(q);
    }

    void setup(Params& params, MasterKey& msk, void (*get_random_bytes)(void*, size_t)) {
        msk.s.random(get_random_bytes);
        params.p.random_generator(get_random_bytes);
        params.sp.multiply_wnaf(params.p, msk.s);
    }

    void keygen(SecretKey& sk, const MasterKey& msk, const ID& id) {
        G1 sq;
        sq.multiply_wnaf(id.q, msk.s);
        sk.sq.from_projective(sq);
    }

    struct SymmetricKeyHashBuffer {
        bls12_381::Encoding<G1Affine, true> q;
        bls12_381::Encoding<G2Affine, true> rp;
        uint8_t pairing[sizeof(GT)];
    };

    void encrypt(Ciphertext& ciphertext, void* symmetric, size_t symmetric_length, const Params& params, const ID& id, void (*hash_fill)(void*, size_t, const void*, size_t), void (*get_random_bytes)(void*, size_t)) {
        Scalar r;
        r.random(get_random_bytes);

        bls12_381::WnafScalar<256, 4> wr;
        wr.from_bigint(r);

        G2 rp;
        rp.multiply_wnaf(params.p, wr);
        ciphertext.rp.from_projective(rp);

        G2 rsp;
        rsp.multiply_wnaf(params.sp, wr);

        SymmetricKeyHashBuffer buffer;

        {
            G2Affine rspaffine;
            rspaffine.from_projective(rsp);

            GT result;
            bls12_381::pairing(result, id.q, rspaffine);

            buffer.q.encode(id.q);
            buffer.rp.encode(ciphertext.rp);
            result.write_big_endian(buffer.pairing);
        }

        hash_fill(symmetric, symmetric_length, &buffer, sizeof(buffer));
    }

    void decrypt(void* symmetric, size_t symmetric_length, const Ciphertext& ciphertext, const SecretKey& sk, const ID& id, void (*hash_fill)(void*, size_t, const void*, size_t)) {
        SymmetricKeyHashBuffer buffer;

        {
            GT result;
            bls12_381::pairing(result, sk.sq, ciphertext.rp);

            buffer.q.encode(id.q);
            buffer.rp.encode(ciphertext.rp);
            result.write_big_endian(buffer.pairing);
        }

        hash_fill(symmetric, symmetric_length, &buffer, sizeof(buffer));
    }
}
