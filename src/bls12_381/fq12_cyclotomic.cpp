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

/*
 * Although I wrote this code, it is based on techniques used by RELIC (see
 * https://github.com/relic-toolkit/relic), specifically in the file
 * src/fpx/relic_fp12_sqr.c, last modified (at the time of writing) in commit
 * 606e84d4177bcff00d5bdd1b8f494508700fb856 in that repository. I am using
 * RELIC under the Apache 2.0 License (which RELIC provides as a licensing
 * option, at the time of writing), so the corresponding functions below are
 * also subject to the Apache 2.0 License.
 */

#include "bls12_381/fq2.hpp"
#include "bls12_381/fq6.hpp"
#include "bls12_381/fq12.hpp"
#include "bls12_381/pairing.hpp"
#include "bls12_381/decomposition.hpp"

namespace embedded_pairing::bls12_381 {
    // static constexpr BigInt<128> bls_x_squared = {.std_words = {0x00000000, 0x00000001, 0x0001a402, 0xac45a401}};
    // static constexpr BigInt<192> bls_x_cubed = {.std_words = {0x00000000, 0x00010000, 0x76030000, 0xec030002, 0x760304d0, 0x8d51ccce}};
    void Fq12::square_cyclotomic(const Fq12& a) {
        Fq2 t2;
        t2.square(a.c0.c0);

        Fq2 t3;
        t3.square(a.c1.c1);

        Fq2 t1;
        t1.add(a.c0.c0, a.c1.c1);

        Fq2 t0;
        t0.multiply_by_nonresidue(t3);
        t0.add(t0, t2);

        t1.square(t1);
        t1.subtract(t1, t2);
        t1.subtract(t1, t3);

        Fq2 c0c0;
        c0c0.copy(a.c0.c0);
        this->c0.c0.subtract(t0, c0c0);
        this->c0.c0.multiply2(this->c0.c0);
        this->c0.c0.add(this->c0.c0, t0);

        this->c1.c1.add(a.c1.c1, t1);
        this->c1.c1.multiply2(this->c1.c1);
        this->c1.c1.add(this->c1.c1, t1);

        Fq2 t5;
        t0.square(a.c0.c1);
        t1.square(a.c1.c2);
        t5.add(a.c0.c1, a.c1.c2);
        t2.square(t5);

        t3.add(t0, t1);
        t5.subtract(t2, t3);

        Fq2 t6;
        t6.add(a.c1.c0, a.c0.c2);
        t3.square(t6);
        t2.square(a.c1.c0);

        t6.multiply_by_nonresidue(t5);
        t5.add(t6, a.c1.c0);
        t5.multiply2(t5);
        this->c1.c0.add(t5, t6);

        Fq2 t4;
        t4.multiply_by_nonresidue(t1);
        t5.add(t0, t4);
        t6.subtract(t5, a.c0.c2);

        t1.square(a.c0.c2);

        t6.multiply2(t6);
        this->c0.c2.add(t6, t5);

        t4.multiply_by_nonresidue(t1);
        t5.add(t2, t4);
        t6.subtract(t5, a.c0.c1);
        t6.multiply2(t6);
        this->c0.c1.add(t6, t5);

        t0.add(t2, t1);
        t5.subtract(t3, t0);
        t6.add(t5, a.c1.c2);
        t6.multiply2(t6);
        this->c1.c2.add(t5, t6);
    }

    void Fq12::map_to_cyclotomic(const Fq12& a) {
        Fq12 t;
        t.inverse(a);
        this->conjugate(a);
        this->multiply(*this, t);

        t.frobenius_map(*this, 2);
        this->multiply(*this, t);
    }

    /*
     * This method computes a^(c0 + c1*|x| + c2*|x|^2 + c3*|x|^3). It uses the
     * fact that r = x^4 - x^2 + 1 and q = (x - 1)^2 * r * 3^(-1) + x, which
     * implies that, if |a| = r (which is true for a in GT), then a^q = a^x.
     * Therefore, we can use the frobenius map to calculate a^x, speeding up
     * computation substantially (only one-fourth as many squares).
     */
    void Fq12::exponentiate_gt(const Fq12& a, const PowersOfX& scalar) {
        /* t[i] contains a^(x^i), which is equal to a^(p^i). */
        Fq12 t[4];
        for (unsigned int i = 0; i != 4; i++) {
            t[i].frobenius_map(a, i);
            if (((i & 0x1) == 0) != bls_x_is_negative) {
                t[i].conjugate(t[i]);
            }
        }

        this->copy(Fq12::one);
        bool found_one = false;
        for (int i = bls_x_highest_set_bit; i != -1; i--) {
            if (found_one) {
                this->square_cyclotomic(*this);
            }
            for (unsigned int j = 0; j != 4; j++) {
                if (scalar.c[j].bit(i)) {
                    this->multiply(*this, t[j]);
                    found_one = true;
                }
            }
        }
    }

    /*
     * Sets this to a ^ power, using division to decompose power. This may not
     * be performant on systems where division is slow (e.g., systems that
     * do not have hardware division support, or systems that do not support
     * 64-bit words).
     */
    void Fq12::exponentiate_gt_div(const Fq12& a, const BigInt<256>& power) {
        PowersOfX scalar;
        scalar.decompose(power);
        this->exponentiate_gt(a, scalar);
    }

    void Fq12::random_gt(BigInt<256>& y, const Fq12& base, void (*get_random_bytes)(void*, size_t)) {
        PowersOfX scalar;
        scalar.random(y, get_random_bytes);
        this->exponentiate_gt(base, scalar);
    }
}
