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

#ifndef EMBEDDED_PAIRING_BLS12_381_PAIRING_HPP_
#define EMBEDDED_PAIRING_BLS12_381_PAIRING_HPP_

#include "core/bigint.hpp"
#include "bls12_381/fq.hpp"
#include "bls12_381/fq2.hpp"
#include "bls12_381/fq6.hpp"
#include "bls12_381/fq12.hpp"
#include "bls12_381/curve.hpp"

using embedded_pairing::core::BigInt;

namespace embedded_pairing::bls12_381 {
    static constexpr BigInt<64> bls_x = {.std_words = {0x00010000, 0xd2010000}};
    static constexpr unsigned int bls_x_num_set_bits = 6;
    static constexpr unsigned int bls_x_highest_set_bit = 63;
    static constexpr bool bls_x_is_negative = true;

    struct MillerTriple {
        Fq2 a;
        Fq2 b;
        Fq2 c;
    };

    /*
     * NOTE: This structure is approximately 20 KiB in size, so use with
     * caution.
     */
    struct G2Prepared {
        static constexpr unsigned int num_coeffs = bls_x_highest_set_bit + bls_x_num_set_bits - 1;

        MillerTriple coeffs[num_coeffs];
        bool infinity;

        bool is_zero() const {
            return this->infinity;
        }
        void prepare(const G2Affine& g2);
    };

    struct AffinePair;
    struct PreparedPair;

    void miller_loop(Fq12& result, AffinePair* pairs, unsigned int num_pairs);
    void miller_loop(Fq12& result, PreparedPair* pairs, unsigned int num_pairs);
    void miller_loop(Fq12& result, const G1Affine& g1, const G2Affine& g2);
    void miller_loop(Fq12& result, const G1Affine& g1, const G2Prepared& g2);

    struct AffinePair {
        friend void miller_loop(Fq12& result, AffinePair* pairs, unsigned int num_pairs);

        const G1Affine* g1;
        const G2Affine* g2;

    private:
        G2 r;
    };

    struct PreparedPair {
        friend void miller_loop(Fq12& result, PreparedPair* pairs, unsigned int num_pairs);

        const G1Affine* g1;
        const G2Prepared* g2;

    private:
        unsigned int coeff_idx;
    };

    void final_exponentiation(Fq12& result, const Fq12& a);

    template <typename GroupPair>
    void pairing_product(Fq12& result, GroupPair* pairs, unsigned int num_pairs) {
        miller_loop(result, pairs, num_pairs);
        final_exponentiation(result, result);
    }

    template <typename G2Type>
    void pairing(Fq12& result, const G1Affine& g1, const G2Type& g2) {
        miller_loop(result, g1, g2);
        final_exponentiation(result, result);
    }

    /* Pairing of G1Affine::generator and G2Affine::generator. */
    static constexpr Fq12 generator_pairing = {
        .c0 = {
            .c0 = {
                .c0 = {{{{
                    .std_words = {0xa01f85c5, 0x1972e433, 0xfd772538, 0x97d32b76, 0xc96bcdf9, 0xc8ce546f, 0x66d40614, 0xcef63e73, 0x81843780, 0xa6113427, 0x3fc6d825, 0x13f3448a}
                }}}},
                .c1 = {{{{
                    .std_words = {0x2e9d6995, 0xd26331b0, 0xf7797e7d, 0x9d68a482, 0x8d39ea92, 0x9c9b2924, 0xe13107aa, 0xf4801ca2, 0xbdbcb066, 0xa16c0732, 0xba360478, 0x83ca4af}
                }}}}
            },
            .c1 = {
                .c0 = {{{{
                    .std_words = {0x916b641, 0x59e261db, 0xb23e960d, 0x2716b6f4, 0xa0bd9c45, 0xc8e55b10, 0x9c4deda8, 0xbdb0bd9, 0x57fdaac5, 0x8cf89ebf, 0x9e777a5e, 0x12d6b792}
                }}}},
                .c1 = {{{{
                    .std_words = {0xb0e15f35, 0x5fc85188, 0x8f096365, 0x34a06e3a, 0xe02ad62c, 0xdb3126a6, 0x7d9a990b, 0xfc6f5aa9, 0xeb89c210, 0xa12f55f5, 0x926f8889, 0x1723703a}
                }}}}
            },
            .c2 = {
                .c0 = {{{{
                    .std_words = {0x71828778, 0x93588f29, 0x11ab7585, 0x43f65b86, 0xec279fdf, 0x3183aaf5, 0x8ac99df6, 0xfa73d7e1, 0xa64c99b0, 0x64e176a6, 0x58388f1f, 0x179fa78c}
                }}}},
                .c1 = {{{{
                    .std_words = {0xca2aef12, 0x672a0a11, 0x2aa3f16b, 0xd11b9b5, 0x699d056e, 0xa44412d0, 0x221a5ba5, 0xc01d0177, 0x6c735529, 0x66e0cede, 0x9fddc339, 0x5f5a71e}
                }}}}
            }
        },
        .c1 = {
            .c0 = {
                .c0 = {{{{
                    .std_words = {0xb062c679, 0xd30a88a1, 0x35fc8304, 0x5ac56a5d, 0xa81f290d, 0xd0c834a6, 0xda3707c7, 0xcd5430c2, 0x80500af0, 0xf0c27ff7, 0xe2d72eae, 0x9245da6}
                }}}},
                .c1 = {{{{
                    .std_words = {0x791b5156, 0x9f2e0676, 0x4918fe13, 0xe2d1c823, 0x3c561bf4, 0x4c9e459f, 0xb9d3e3c1, 0xa3e85e53, 0x21a70020, 0x820a121e, 0x41c59acc, 0x15af6183}
                }}}}
            },
            .c1 = {
                .c0 = {{{{
                    .std_words = {0x24993ab1, 0x7c95658c, 0x1ca886b9, 0x73eb3872, 0x477434bc, 0x5256d749, 0xea504a8b, 0x8ba41902, 0xc86ce6d, 0x4a3d3f8, 0xfb686eaa, 0x18a64a87}
                }}}},
                .c1 = {{{{
                    .std_words = {0xb920cf26, 0xbb83e71b, 0x92a73945, 0x2a5277ac, 0x94f046a0, 0xfc0ee59f, 0x786058f7, 0x7158cdf3, 0x82f945f6, 0x7cc1061b, 0x9fdbe567, 0x3f847aa}
                }}}}
            },
            .c2 = {
                .c0 = {{{{
                    .std_words = {0x6134e657, 0x8078dba5, 0x43998a6e, 0x1cd7ec9a, 0x1a993766, 0xb1aa599a, 0x842ee44, 0xc9a0f62f, 0xb605dffa, 0x8e159be3, 0x4af13fc2, 0xc86ba0d}
                }}}},
                .c1 = {{{{
                    .std_words = {0x6a52ffb1, 0xe80ff2a0, 0x721a906c, 0x7694ca48, 0x3b08514, 0x7583183e, 0x40cee4e2, 0xf567afdd, 0xe526a5fc, 0x9a6d96d2, 0x861f2242, 0x197e9f49}
                }}}}
            }
        }
    };
}

#endif
