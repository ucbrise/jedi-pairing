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

#include "wkdibe/wkdibe.h"

#include <stddef.h>

#include "wkdibe/api.hpp"

using namespace embedded_pairing::wkdibe;

void embedded_pairing_wkdibe_scalar_hash_reduce(embedded_pairing_wkdibe_scalar_t* x) {
    scalar_hash_reduce(*reinterpret_cast<Scalar*>(x));
}

void embedded_pairing_wkdibe_random_zpstar(embedded_pairing_wkdibe_scalar_t* x, void (*get_random_bytes)(void*, size_t)) {
    random_zpstar(*reinterpret_cast<Scalar*>(x), get_random_bytes);
}

void embedded_pairing_wkdibe_random_g1(embedded_pairing_wkdibe_g1_t* g1, void (*get_random_bytes)(void*, size_t)) {
    random_g1(*reinterpret_cast<G1*>(g1), get_random_bytes);
}

void embedded_pairing_wkdibe_random_g2(embedded_pairing_wkdibe_g2_t* g2, void (*get_random_bytes)(void*, size_t)) {
    random_g2(*reinterpret_cast<G2*>(g2), get_random_bytes);
}

void embedded_pairing_wkdibe_random_gt(embedded_pairing_wkdibe_gt_t* gt, void (*get_random_bytes)(void*, size_t)) {
    random_gt(*reinterpret_cast<GT*>(gt), get_random_bytes);
}

void embedded_pairing_wkdibe_setup(embedded_pairing_wkdibe_params_t* params, embedded_pairing_wkdibe_masterkey_t* msk, int l, bool signatures, void (*get_random_bytes)(void*, size_t)) {
    setup(*reinterpret_cast<Params*>(params), *reinterpret_cast<MasterKey*>(msk), l, signatures, get_random_bytes);
}

void embedded_pairing_wkdibe_keygen(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_masterkey_t* msk, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t)) {
    keygen(*reinterpret_cast<SecretKey*>(sk), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const MasterKey*>(msk), *reinterpret_cast<const AttributeList*>(attrs), get_random_bytes);
}

void embedded_pairing_wkdibe_qualifykey(embedded_pairing_wkdibe_secretkey_t* qualified, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t)) {
    qualifykey(*reinterpret_cast<SecretKey*>(qualified), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const SecretKey*>(sk), *reinterpret_cast<const AttributeList*>(attrs), get_random_bytes);
}

void embedded_pairing_wkdibe_nondelegable_keygen(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_masterkey_t* msk, const embedded_pairing_wkdibe_attributelist_t* attrs) {
    nondelegable_keygen(*reinterpret_cast<SecretKey*>(sk), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const MasterKey*>(msk), *reinterpret_cast<const AttributeList*>(attrs));
}

void embedded_pairing_wkdibe_nondelegable_qualifykey(embedded_pairing_wkdibe_secretkey_t* qualified, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs) {
    nondelegable_qualifykey(*reinterpret_cast<SecretKey*>(qualified), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const SecretKey*>(sk), *reinterpret_cast<const AttributeList*>(attrs));
}

void embedded_pairing_wkdibe_adjust_nondelegable(embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_secretkey_t* parent, const embedded_pairing_wkdibe_attributelist_t* from, const embedded_pairing_wkdibe_attributelist_t* to) {
    adjust_nondelegable(*reinterpret_cast<SecretKey*>(sk), *reinterpret_cast<const SecretKey*>(parent), *reinterpret_cast<const AttributeList*>(from), *reinterpret_cast<const AttributeList*>(to));
}

void embedded_pairing_wkdibe_precompute(embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs) {
    precompute(*reinterpret_cast<Precomputed*>(precomputed), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const AttributeList*>(attrs));
}

void embedded_pairing_wkdibe_adjust_precomputed(embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* from, const embedded_pairing_wkdibe_attributelist_t* to) {
    adjust_precomputed(*reinterpret_cast<Precomputed*>(precomputed), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const AttributeList*>(from), *reinterpret_cast<const AttributeList*>(to));
}

void embedded_pairing_wkdibe_resamplekey(embedded_pairing_wkdibe_secretkey_t* resampled, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_secretkey_t* sk, bool supportFurtherQualification, void (*get_random_bytes)(void*, size_t)) {
    resamplekey(*reinterpret_cast<SecretKey*>(resampled), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const Precomputed*>(precomputed), *reinterpret_cast<const SecretKey*>(sk), supportFurtherQualification, get_random_bytes);
}

void embedded_pairing_wkdibe_encrypt(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs, void (*get_random_bytes)(void*, size_t)) {
    encrypt(*reinterpret_cast<Ciphertext*>(ciphertext), *reinterpret_cast<const GT*>(message), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const AttributeList*>(attrs), get_random_bytes);
}

void embedded_pairing_wkdibe_encrypt_precomputed(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, void (*get_random_bytes)(void*, size_t)) {
    encrypt_precomputed(*reinterpret_cast<Ciphertext*>(ciphertext), *reinterpret_cast<const GT*>(message), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const Precomputed*>(precomputed), get_random_bytes);
}

void embedded_pairing_wkdibe_decrypt(embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_secretkey_t* sk) {
    decrypt(*reinterpret_cast<GT*>(message), *reinterpret_cast<const Ciphertext*>(ciphertext), *reinterpret_cast<const SecretKey*>(sk));
}

void embedded_pairing_wkdibe_decrypt_master(embedded_pairing_wkdibe_gt_t* message, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, const embedded_pairing_wkdibe_masterkey_t* msk) {
    decrypt_master(*reinterpret_cast<GT*>(message), *reinterpret_cast<const Ciphertext*>(ciphertext), *reinterpret_cast<const MasterKey*>(msk));
}

void embedded_pairing_wkdibe_sign(embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_scalar_t* message, void (*get_random_bytes)(void*, size_t)) {
    sign(*reinterpret_cast<Signature*>(signature), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const SecretKey*>(sk), reinterpret_cast<const AttributeList*>(attrs), *reinterpret_cast<const Scalar*>(message), get_random_bytes);
}

void embedded_pairing_wkdibe_sign_precomputed(embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_secretkey_t* sk, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_scalar_t* message, void (*get_random_bytes)(void*, size_t)) {
    sign_precomputed(*reinterpret_cast<Signature*>(signature), *reinterpret_cast<const Params*>(params), *reinterpret_cast<const SecretKey*>(sk), reinterpret_cast<const AttributeList*>(attrs), *reinterpret_cast<const Precomputed*>(precomputed), *reinterpret_cast<const Scalar*>(message), get_random_bytes);
}

bool embedded_pairing_wkdibe_verify(const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_attributelist_t* attrs, const embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_scalar_t* message) {
    return verify(*reinterpret_cast<const Params*>(params), *reinterpret_cast<const AttributeList*>(attrs), *reinterpret_cast<const Signature*>(signature), *reinterpret_cast<const Scalar*>(message));
}

bool embedded_pairing_wkdibe_verify_precomputed(const embedded_pairing_wkdibe_params_t* params, const embedded_pairing_wkdibe_precomputed_t* precomputed, const embedded_pairing_wkdibe_signature_t* signature, const embedded_pairing_wkdibe_scalar_t* message) {
    return verify_precomputed(*reinterpret_cast<const Params*>(params), *reinterpret_cast<const Precomputed*>(precomputed), *reinterpret_cast<const Signature*>(signature), *reinterpret_cast<const Scalar*>(message));
}

void embedded_pairing_wkdibe_params_marshal(void* buffer, const embedded_pairing_wkdibe_params_t* params, bool compressed) {
    if (compressed) {
        reinterpret_cast<const Params*>(params)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const Params*>(params)->marshal<false>(buffer);
    }
}

bool embedded_pairing_wkdibe_params_unmarshal(embedded_pairing_wkdibe_params_t* params, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<Params*>(params)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<Params*>(params)->unmarshal<false>(buffer, checked);
    }
}

int embedded_pairing_wkdibe_params_set_length(embedded_pairing_wkdibe_params_t* params, const void* marshalled, size_t marshalled_length, bool compressed) {
    if (compressed) {
        return reinterpret_cast<Params*>(params)->setLength<true>(marshalled, marshalled_length);
    } else {
        return reinterpret_cast<Params*>(params)->setLength<false>(marshalled, marshalled_length);
    }
}

size_t embedded_pairing_wkdibe_params_get_marshalled_length(const embedded_pairing_wkdibe_params_t* params, bool compressed) {
    if (compressed) {
        return reinterpret_cast<const Params*>(params)->getMarshalledLength<true>();
    } else {
        return reinterpret_cast<const Params*>(params)->getMarshalledLength<false>();
    }
}

int embedded_pairing_wkdibe_params_unmarshalled_length(const void* marshalled, size_t marshalled_length, bool compressed) {
    if (compressed) {
        return Params::unmarshalledLength<true>(marshalled, marshalled_length);
    } else {
        return Params::unmarshalledLength<false>(marshalled, marshalled_length);
    }
}

size_t embedded_pairing_wkdibe_params_marshalled_length(int length, bool signatures, bool compressed) {
    if (compressed) {
        return Params::marshalledLength<true>(length, signatures);
    } else {
        return Params::marshalledLength<false>(length, signatures);
    }
}

void embedded_pairing_wkdibe_ciphertext_marshal(void* buffer, const embedded_pairing_wkdibe_ciphertext_t* ciphertext, bool compressed) {
    if (compressed) {
        reinterpret_cast<const Ciphertext*>(ciphertext)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const Ciphertext*>(ciphertext)->marshal<false>(buffer);
    }
}

bool embedded_pairing_wkdibe_ciphertext_unmarshal(embedded_pairing_wkdibe_ciphertext_t* ciphertext, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<Ciphertext*>(ciphertext)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<Ciphertext*>(ciphertext)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_wkdibe_ciphertext_get_marshalled_length(bool compressed) {
    if (compressed) {
        return Ciphertext::marshalledLength<true>;
    } else {
        return Ciphertext::marshalledLength<false>;
    }
}

void embedded_pairing_wkdibe_signature_marshal(void* buffer, const embedded_pairing_wkdibe_signature_t* signature, bool compressed) {
    if (compressed) {
        reinterpret_cast<const Signature*>(signature)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const Signature*>(signature)->marshal<false>(buffer);
    }
}

bool embedded_pairing_wkdibe_signature_unmarshal(embedded_pairing_wkdibe_signature_t* signature, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<Signature*>(signature)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<Signature*>(signature)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_wkdibe_signature_get_marshalled_length(bool compressed) {
    if (compressed) {
        return Signature::marshalledLength<true>;
    } else {
        return Signature::marshalledLength<false>;
    }
}

void embedded_pairing_wkdibe_secretkey_marshal(void* buffer, const embedded_pairing_wkdibe_secretkey_t* secretkey, bool compressed) {
    if (compressed) {
        reinterpret_cast<const SecretKey*>(secretkey)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const SecretKey*>(secretkey)->marshal<false>(buffer);
    }
}

bool embedded_pairing_wkdibe_secretkey_unmarshal(embedded_pairing_wkdibe_secretkey_t* secretkey, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<SecretKey*>(secretkey)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<SecretKey*>(secretkey)->unmarshal<false>(buffer, checked);
    }
}

int embedded_pairing_wkdibe_secretkey_set_length(embedded_pairing_wkdibe_secretkey_t* secretkey, const void* marshalled, size_t marshalled_length, bool compressed) {
    if (compressed) {
        return reinterpret_cast<SecretKey*>(secretkey)->setLength<true>(marshalled, marshalled_length);
    } else {
        return reinterpret_cast<SecretKey*>(secretkey)->setLength<false>(marshalled, marshalled_length);
    }
}

size_t embedded_pairing_wkdibe_secretkey_get_marshalled_length(const embedded_pairing_wkdibe_secretkey_t* secretkey, bool compressed) {
    if (compressed) {
        return reinterpret_cast<const SecretKey*>(secretkey)->getMarshalledLength<true>();
    } else {
        return reinterpret_cast<const SecretKey*>(secretkey)->getMarshalledLength<false>();
    }
}

int embedded_pairing_wkdibe_secretkey_unmarshalled_length(const void* marshalled, size_t marshalled_length, bool compressed) {
    if (compressed) {
        return SecretKey::unmarshalledLength<true>(marshalled, marshalled_length);
    } else {
        return SecretKey::unmarshalledLength<false>(marshalled, marshalled_length);
    }
}

size_t embedded_pairing_wkdibe_secretkey_marshalled_length(int length, bool signatures, bool compressed) {
    if (compressed) {
        return SecretKey::marshalledLength<true>(length, signatures);
    } else {
        return SecretKey::marshalledLength<false>(length, signatures);
    }
}

void embedded_pairing_wkdibe_masterkey_marshal(void* buffer, const embedded_pairing_wkdibe_masterkey_t* masterkey, bool compressed) {
    if (compressed) {
        reinterpret_cast<const MasterKey*>(masterkey)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const MasterKey*>(masterkey)->marshal<false>(buffer);
    }
}

bool embedded_pairing_wkdibe_masterkey_unmarshal(embedded_pairing_wkdibe_masterkey_t* masterkey, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<MasterKey*>(masterkey)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<MasterKey*>(masterkey)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_wkdibe_masterkey_get_marshalled_length(bool compressed) {
    if (compressed) {
        return MasterKey::marshalledLength<true>;
    } else {
        return MasterKey::marshalledLength<false>;
    }
}
