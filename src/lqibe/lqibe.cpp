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

#include "lqibe/lqibe.h"

#include <stddef.h>

#include "lqibe/api.hpp"

using namespace embedded_pairing::lqibe;

void embedded_pairing_lqibe_compute_id_from_hash(embedded_pairing_lqibe_id_t* id, const embedded_pairing_lqibe_idhash_t* hash) {
    compute_id_from_hash(*reinterpret_cast<ID*>(id), *reinterpret_cast<const IDHash*>(hash));
}

void embedded_pairing_lqibe_setup(embedded_pairing_lqibe_params_t* params, embedded_pairing_lqibe_masterkey_t* msk, void (*get_random_bytes)(void*, size_t)) {
    setup(*reinterpret_cast<Params*>(params), *reinterpret_cast<MasterKey*>(msk), get_random_bytes);
}

void embedded_pairing_lqibe_keygen(embedded_pairing_lqibe_secretkey_t* sk, const embedded_pairing_lqibe_masterkey_t* msk, const embedded_pairing_lqibe_id_t* id) {
    keygen(*reinterpret_cast<SecretKey*>(sk), *reinterpret_cast<const MasterKey*>(msk), *reinterpret_cast<const ID*>(id));
}

void embedded_pairing_lqibe_encrypt(embedded_pairing_lqibe_ciphertext_t* ciphertext, void* symmetric, size_t symmetric_length, const embedded_pairing_lqibe_params_t* params, const embedded_pairing_lqibe_id_t* id, void (*hash_fill)(void*, size_t, const void*, size_t), void (*get_random_bytes)(void*, size_t)) {
    encrypt(*reinterpret_cast<Ciphertext*>(ciphertext), symmetric, symmetric_length, *reinterpret_cast<const Params*>(params), *reinterpret_cast<const ID*>(id), hash_fill, get_random_bytes);
}

void embedded_pairing_lqibe_decrypt(void* symmetric, size_t symmetric_length, const embedded_pairing_lqibe_ciphertext_t* ciphertext, const embedded_pairing_lqibe_secretkey_t* sk, const embedded_pairing_lqibe_id_t* id, void (*hash_fill)(void*, size_t, const void*, size_t)) {
    decrypt(symmetric, symmetric_length, *reinterpret_cast<const Ciphertext*>(ciphertext), *reinterpret_cast<const SecretKey*>(sk), *reinterpret_cast<const ID*>(id), hash_fill);
}

void embedded_pairing_lqibe_params_marshal(void* buffer, const embedded_pairing_lqibe_params_t* params, bool compressed) {
    if (compressed) {
        reinterpret_cast<const Params*>(params)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const Params*>(params)->marshal<false>(buffer);
    }
}

bool embedded_pairing_lqibe_params_unmarshal(embedded_pairing_lqibe_params_t* params, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<Params*>(params)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<Params*>(params)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_lqibe_params_get_marshalled_length(bool compressed) {
    if (compressed) {
        return Params::marshalledLength<true>;
    } else {
        return Params::marshalledLength<false>;
    }
}

void embedded_pairing_lqibe_id_marshal(void* buffer, const embedded_pairing_lqibe_id_t* id, bool compressed) {
    if (compressed) {
        reinterpret_cast<const ID*>(id)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const ID*>(id)->marshal<false>(buffer);
    }
}

bool embedded_pairing_lqibe_id_unmarshal(embedded_pairing_lqibe_id_t* id, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<ID*>(id)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<ID*>(id)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_lqibe_id_get_marshalled_length(bool compressed) {
    if (compressed) {
        return ID::marshalledLength<true>;
    } else {
        return ID::marshalledLength<false>;
    }
}

void embedded_pairing_lqibe_masterkey_marshal(void* buffer, const embedded_pairing_lqibe_masterkey_t* masterkey, bool compressed) {
    if (compressed) {
        reinterpret_cast<const MasterKey*>(masterkey)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const MasterKey*>(masterkey)->marshal<false>(buffer);
    }
}

bool embedded_pairing_lqibe_masterkey_unmarshal(embedded_pairing_lqibe_masterkey_t* masterkey, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<MasterKey*>(masterkey)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<MasterKey*>(masterkey)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_lqibe_masterkey_get_marshalled_length(bool compressed) {
    if (compressed) {
        return MasterKey::marshalledLength<true>;
    } else {
        return MasterKey::marshalledLength<false>;
    }
}

void embedded_pairing_lqibe_secretkey_marshal(void* buffer, const embedded_pairing_lqibe_secretkey_t* secretkey, bool compressed) {
    if (compressed) {
        reinterpret_cast<const SecretKey*>(secretkey)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const SecretKey*>(secretkey)->marshal<false>(buffer);
    }
}

bool embedded_pairing_lqibe_secretkey_unmarshal(embedded_pairing_lqibe_secretkey_t* secretkey, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<SecretKey*>(secretkey)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<SecretKey*>(secretkey)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_lqibe_secretkey_get_marshalled_length(bool compressed) {
    if (compressed) {
        return SecretKey::marshalledLength<true>;
    } else {
        return SecretKey::marshalledLength<false>;
    }
}

void embedded_pairing_lqibe_ciphertext_marshal(void* buffer, const embedded_pairing_lqibe_ciphertext_t* ciphertext, bool compressed) {
    if (compressed) {
        reinterpret_cast<const Ciphertext*>(ciphertext)->marshal<true>(buffer);
    } else {
        reinterpret_cast<const Ciphertext*>(ciphertext)->marshal<false>(buffer);
    }
}

bool embedded_pairing_lqibe_ciphertext_unmarshal(embedded_pairing_lqibe_ciphertext_t* ciphertext, const void* buffer, bool compressed, bool checked) {
    if (compressed) {
        return reinterpret_cast<Ciphertext*>(ciphertext)->unmarshal<true>(buffer, checked);
    } else {
        return reinterpret_cast<Ciphertext*>(ciphertext)->unmarshal<false>(buffer, checked);
    }
}

size_t embedded_pairing_lqibe_ciphertext_get_marshalled_length(bool compressed) {
    if (compressed) {
        return Ciphertext::marshalledLength<true>;
    } else {
        return Ciphertext::marshalledLength<false>;
    }
}
