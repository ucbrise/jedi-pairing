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

#include <stddef.h>

#include "core/montgomeryfp_utils.hpp"
#include "bls12_381/pairing.hpp"

namespace embedded_pairing::wkdibe {
    void setup(Params& params, MasterKey& msk, int l, bool signatures, void (*get_random_bytes)(void*, size_t)) {
        Scalar alpha;
        random_zpstar(alpha, get_random_bytes);
        params.g.random_generator(get_random_bytes);
        params.g1.multiply(params.g, alpha);
        params.g2.random_generator(get_random_bytes);
        msk.g2alpha.multiply(params.g2, alpha);
        params.g3.random_generator(get_random_bytes);

        G1Affine g2affine;
        G2Affine g1affine;
        g2affine.from_projective(params.g2);
        g1affine.from_projective(params.g1);
        bls12_381::pairing(params.pairing, g2affine, g1affine);

        params.l = l;
        params.signatures = signatures;
        if (signatures) {
            params.hsig.random_generator(get_random_bytes);
        } else {
            params.hsig.copy(G1::zero);
        }
        for (int i = 0; i != l; i++) {
            params.h[i].random_generator(get_random_bytes);
        }
    }

    void keygen(SecretKey& sk, const Params& params, const MasterKey& msk, const AttributeList& attrs, void (*get_random_bytes)(void*, size_t)) {
        Scalar r;
        G1 temp;
        random_zpstar(r, get_random_bytes);
        sk.a0.copy(params.g3);
        int j = 0; /* Index for writing to qualified.b */
        int k = 0; /* Index for reading from attrs.attrs */
        for (int i = 0; i != params.l; i++) {
            if (k != attrs.length && attrs.attrs[k].idx == i) {
                if (!attrs.attrs[k].omitFromKeys) {
                    temp.multiply(params.h[i], attrs.attrs[k].id);
                    sk.a0.add(sk.a0, temp);
                }
                k++;
            } else if (!attrs.omitAllFromKeysUnlessPresent) {
                sk.b[j].idx = i;
                sk.b[j].hexp.multiply(params.h[i], r);
                j++;
            }
        }
        sk.l = j;
        sk.signatures = params.signatures;
        if (sk.signatures) {
            sk.bsig.multiply(params.hsig, r);
        } else {
            sk.bsig.copy(G1::zero);
        }
        sk.a0.multiply(sk.a0, r);
        sk.a0.add(sk.a0, msk.g2alpha);
        sk.a1.multiply(params.g, r);
    }

    void qualifykey(SecretKey& qualified, const Params& params, const SecretKey& sk, const AttributeList& attrs, void (*get_random_bytes)(void*, size_t)) {
        Scalar t;
        G1 temp;
        G1 product;
        random_zpstar(t, get_random_bytes);
        product.copy(params.g3);
        qualified.a0.copy(sk.a0);
        int j = 0; /* Index for writing to qualified.b */
        int k = 0; /* Index for reading from attrs.attrs */
        int x = 0; /* Index for reading from sk.b */
        for (int i = 0; i != params.l; i++) {
            if (k != attrs.length && attrs.attrs[k].idx == i) {
                if (!attrs.attrs[k].omitFromKeys) {
                    temp.multiply(params.h[i], attrs.attrs[k].id);
                    product.add(product, temp);
                    if (sk.b[x].idx == i) {
                        temp.multiply(sk.b[x].hexp, attrs.attrs[k].id);
                        qualified.a0.add(qualified.a0, temp);
                        x++;
                    }
                }
                k++;
            } else if (sk.b[x].idx == i) {
                if (!attrs.omitAllFromKeysUnlessPresent) {
                    qualified.b[j].idx = i;
                    qualified.b[j].hexp.multiply(params.h[i], t);
                    qualified.b[j].hexp.add(qualified.b[j].hexp, sk.b[x].hexp);
                    j++;
                }
                x++;
            }
            /*
             * We could hit neither case if slot i is "hidden" (the b element
             * corresponding to it is not provided, so it can't be filled in).
             */
        }
        qualified.l = j;
        qualified.signatures = sk.signatures;
        if (qualified.signatures) {
            qualified.bsig.multiply(params.hsig, t);
            qualified.bsig.add(qualified.bsig, sk.bsig);
        } else {
            qualified.bsig.copy(G1::zero);
        }
        product.multiply(product, t);
        qualified.a0.add(qualified.a0, product);
        qualified.a1.multiply(params.g, t);
        qualified.a1.add(qualified.a1, sk.a1);
    }

    void nondelegable_keygen(SecretKey& sk, const Params& params, const MasterKey& msk, const AttributeList& attrs) {
        G1 temp;
        sk.a0.copy(params.g3);
        int j = 0; /* Index for writing to qualified.b */
        int k = 0; /* Index for reading from attrs.attrs */
        for (int i = 0; i != params.l; i++) {
            if (k != attrs.length && !attrs.attrs[k].omitFromKeys && attrs.attrs[k].idx == i) {
                temp.multiply(params.h[i], attrs.attrs[k].id);
                sk.a0.add(sk.a0, temp);
                k++;
            } else if (!attrs.omitAllFromKeysUnlessPresent) {
                sk.b[j].idx = i;
                sk.b[j].hexp.copy(params.h[i]);
                j++;
            }
        }
        sk.l = j;
        sk.signatures = params.signatures;
        if (sk.signatures) {
            sk.bsig.copy(params.hsig);
        } else {
            sk.bsig.copy(G1::zero);
        }
        sk.a0.add(sk.a0, msk.g2alpha);
        sk.a1.copy(params.g);
    }

    void nondelegable_qualifykey(SecretKey& qualified, const Params& params, const SecretKey& sk, const AttributeList& attrs) {
        G1 temp;
        qualified.a0.copy(sk.a0);
        int j = 0; /* Index for writing to qualified.b */
        int k = 0; /* Index for reading from attrs.attrs */
        int x = 0; /* Index for reading from sk.b */
        for (int i = 0; i != params.l; i++) {
            if (k != attrs.length && attrs.attrs[k].idx == i) {
                if (sk.b[x].idx == i && !attrs.attrs[k].omitFromKeys) {
                    temp.multiply(sk.b[x].hexp, attrs.attrs[k].id);
                    qualified.a0.add(qualified.a0, temp);
                    x++;
                }
                k++;
            } else if (sk.b[x].idx == i) {
                if (!attrs.omitAllFromKeysUnlessPresent) {
                    qualified.b[j].idx = i;
                    qualified.b[j].hexp.copy(sk.b[x].hexp);
                    j++;
                }
                x++;
            }
            /*
             * We could hit neither case if slot i is "hidden" (the b element
             * corresponding to it is not provided, so it can't be filled in).
             */
        }
        qualified.l = j;
        qualified.signatures = sk.signatures;
        if (qualified.signatures) {
            qualified.bsig.copy(sk.bsig);
        } else {
            qualified.bsig.copy(G1::zero);
        }
        qualified.a1.copy(sk.a1);
    }

    void adjust_nondelegable(SecretKey& sk, const SecretKey& parent, const AttributeList& from, const AttributeList& to) {
        G1 temp;
        Scalar diff;

        sk.l = 0;
        int j = 0;
        int k = 0;
        for (int i = 0; i != parent.l; i++) {
            int idx = parent.b[i].idx;
            while (j != from.length && from.attrs[j].idx < idx && !from.attrs[j].omitFromKeys) {
                j++;
            }
            while (k != to.length && to.attrs[k].idx < idx && !to.attrs[k].omitFromKeys) {
                k++;
            }
            if (j == from.length && k == to.length) {
                break;
            }

            bool sub_from = (j != from.length && from.attrs[j].idx == idx);
            bool add_to = (k != to.length && to.attrs[k].idx == idx);
            if (sub_from && add_to) {
                if (!ID::equal(from.attrs[j].id, to.attrs[k].id)) {
                    if (diff.subtract(to.attrs[k].id, from.attrs[j].id)) {
                        diff.add(diff, group_order);
                    }
                    temp.multiply(parent.b[i].hexp, diff);
                    sk.a0.add(sk.a0, temp);
                }
            } else if (sub_from) {
                diff.subtract(group_order, from.attrs[j].id);
                temp.multiply(parent.b[i].hexp, diff);
                sk.a0.add(sk.a0, temp);
            } else if (add_to) {
                temp.multiply(parent.b[i].hexp, to.attrs[k].id);
                sk.a0.add(sk.a0, temp);
            }
        }
    }

    void precompute(Precomputed& precomputed, const Params& params, const AttributeList& attrs) {
        G1 temp;
        precomputed.prodexp.copy(params.g3);
        for (int i = 0; i != attrs.length; i++) {
            const Attribute& attr = attrs.attrs[i];
            temp.multiply(params.h[attr.idx], attr.id);
            precomputed.prodexp.add(precomputed.prodexp, temp);
        }
    }

    void adjust_precomputed(Precomputed& precomputed, const Params& params, const AttributeList& from, const AttributeList& to) {
        G1 temp;
        Scalar diff;

        int i = 0;
        int j = 0;
        while (i != from.length && j != to.length) {
            const Attribute& from_attr = from.attrs[i];
            const Attribute& to_attr = to.attrs[j];
            if (from_attr.idx == to_attr.idx) {
                if (!ID::equal(from_attr.id, to_attr.id)) {
                    if (diff.subtract(to_attr.id, from_attr.id)) {
                        diff.add(diff, group_order);
                    }
                    temp.multiply(params.h[to_attr.idx], diff);
                    precomputed.prodexp.add(precomputed.prodexp, temp);
                }
                i++;
                j++;
            } else if (from_attr.idx < to_attr.idx) {
                diff.subtract(group_order, from_attr.id);
                temp.multiply(params.h[from_attr.idx], diff);
                precomputed.prodexp.add(precomputed.prodexp, temp);
                i++;
            } else {
                temp.multiply(params.h[to_attr.idx], to_attr.id);
                precomputed.prodexp.add(precomputed.prodexp, temp);
                j++;
            }
        }
        while (i != from.length) {
            const Attribute& from_attr = from.attrs[i];
            diff.subtract(group_order, from_attr.id);
            temp.multiply(params.h[from_attr.idx], diff);
            precomputed.prodexp.add(precomputed.prodexp, temp);
            i++;
        }
        while (j != to.length) {
            const Attribute& to_attr = to.attrs[j];
            temp.multiply(params.h[to_attr.idx], to_attr.id);
            precomputed.prodexp.add(precomputed.prodexp, temp);
            j++;
        }
    }

    void resamplekey(SecretKey& resampled, const Params& params, const Precomputed& precomputed, const SecretKey& sk, bool supportFurtherQualification, void (*get_random_bytes)(void*, size_t)) {
        Scalar t;
        G1 temp;
        G2 temp2;
        random_zpstar(t, get_random_bytes);

        temp.multiply(precomputed.prodexp, t);
        resampled.a0.add(sk.a0, temp);

        temp2.multiply(params.g, t);
        resampled.a1.add(sk.a1, temp2);

        resampled.signatures = sk.signatures;
        if (resampled.signatures) {
            temp.multiply(params.hsig, t);
            resampled.bsig.add(sk.bsig, temp);
        } else {
            resampled.bsig.copy(G1::zero);
        }

        if (supportFurtherQualification) {
            for (int i = 0; i != sk.l; i++) {
                temp.multiply(params.h[sk.b[i].idx], t);
                resampled.b[i].hexp.add(sk.b[i].hexp, temp);
                resampled.b[i].idx = sk.b[i].idx;
            }
            resampled.l = sk.l;
        } else {
            resampled.l = 0;
        }
    }

    void encrypt(Ciphertext& ciphertext, const GT& message, const Params& params, const AttributeList& attrs, void (*get_random_bytes)(void*, size_t)) {
        Precomputed precomputed;
        precompute(precomputed, params, attrs);
        encrypt_precomputed(ciphertext, message, params, precomputed, get_random_bytes);
    }

    void encrypt_precomputed(Ciphertext& ciphertext, const GT& message, const Params& params, const Precomputed& precomputed, void (*get_random_bytes)(void*, size_t)) {
        Scalar s;
        random_zpstar(s, get_random_bytes);
        core::exponentiate(ciphertext.a, params.pairing, s);
        ciphertext.a.multiply(ciphertext.a, message);
        ciphertext.b.multiply(params.g, s);
        ciphertext.c.multiply(precomputed.prodexp, s);
    }

    void decrypt(GT& message, const Ciphertext& ciphertext, const SecretKey& sk) {
        GT denominator;
        G1Affine caffine;
        G2Affine a1affine;
        G1Affine a0affine;
        G2Affine baffine;
        caffine.from_projective(ciphertext.c);
        a1affine.from_projective(sk.a1);
        a0affine.from_projective(sk.a0);
        baffine.from_projective(ciphertext.b);
        bls12_381::pairing(message, caffine, a1affine);
        bls12_381::pairing(denominator, a0affine, baffine);
        denominator.inverse(denominator);
        message.multiply(message, denominator);
        message.multiply(message, ciphertext.a);
    }

    void decrypt_master(GT& message, const Ciphertext& ciphertext, const MasterKey& msk) {
        G1Affine g2alphaaffine;
        G2Affine baffine;
        g2alphaaffine.from_projective(msk.g2alpha);
        baffine.from_projective(ciphertext.b);
        bls12_381::pairing(message, g2alphaaffine, baffine);
        message.inverse(message);
        message.multiply(message, ciphertext.a);
    }

    void sign(Signature& signature, const Params& params, const SecretKey& sk, const AttributeList* attrs, const Scalar& message, void (*get_random_bytes)(void*, size_t)) {
        Precomputed precomputed;
        precompute(precomputed, params, *attrs);
        sign_precomputed(signature, params, sk, attrs, precomputed, message, get_random_bytes);
    }

    void sign_precomputed(Signature& signature, const Params& params, const SecretKey& sk, const AttributeList* attrs, const Precomputed& precomputed, const Scalar& message, void (*get_random_bytes)(void*, size_t)) {
        Scalar s;
        G1 prodexp;
        random_zpstar(s, get_random_bytes);
        signature.a0.multiply(sk.bsig, message);
        signature.a0.add(signature.a0, sk.a0);
        signature.a1.multiply(params.g, s);
        signature.a1.add(signature.a1, sk.a1);

        prodexp.multiply(params.hsig, message);
        prodexp.add(prodexp, precomputed.prodexp);
        prodexp.multiply(prodexp, s);
        signature.a0.add(signature.a0, prodexp);

        if (attrs != nullptr) {
            int k = 0;
            for (int i = 0; i != sk.l; i++) {
                while (k != attrs->length && attrs->attrs[k].idx < sk.b[i].idx) {
                    k++;
                }
                if (k == attrs->length) {
                    return;
                }
                if (sk.b[i].idx == attrs->attrs[k].idx) {
                    prodexp.multiply(sk.b[i].hexp, attrs->attrs[k].id);
                    signature.a0.add(signature.a0, prodexp);
                    k++;
                }
            }
        }
    }

    bool verify(const Params& params, const AttributeList& attrs, const Signature& signature, const Scalar& message) {
        Precomputed precomputed;
        precompute(precomputed, params, attrs);
        return verify_precomputed(params, precomputed, signature, message);
    }

    bool verify_precomputed(const Params& params, const Precomputed& precomputed, const Signature& signature, const Scalar& message) {
        GT ratio;
        GT denominator;
        G1 prodexp;
        prodexp.multiply(params.hsig, message);
        prodexp.add(prodexp, precomputed.prodexp);
        G1Affine a0affine;
        G2Affine gaffine;
        G1Affine prodexpaffine;
        G2Affine a1affine;
        a0affine.from_projective(signature.a0);
        gaffine.from_projective(params.g);
        prodexpaffine.from_projective(prodexp);
        a1affine.from_projective(signature.a1);
        bls12_381::pairing(ratio, a0affine, gaffine);
        bls12_381::pairing(denominator, prodexpaffine, a1affine);
        denominator.inverse(denominator);
        ratio.multiply(ratio, denominator);
        return GT::equal(ratio, params.pairing);
    }
}