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

#ifndef EMBEDDED_PAIRING_CORE_FP_UTILS_HPP_
#define EMBEDDED_PAIRING_CORE_FP_UTILS_HPP_

#include "./bigint.hpp"
#include "./fp.hpp"

namespace embedded_pairing::core {
    /*
     * We define 'exponentiate' as a separate function for two reasons:
     * 1) The same algorithm, namely repeated squaring, works for a
     *    variety of types, so I didn't want to implement it as a
     *    method of a particular class.
     * 2) It uses the F type as a black box, so we would like it to
     *    use assembly-optimized method implementations in a subclass
     *    should they be present. We could also acheive this by making
     *    all such methods virtual, but we want all our types to be
     *    PODs, meaning they cannot have any virtual methods.
     */

    /*
     * Currently, for small powers, this spends most of its time squaring one.
     * It's an open question whether we should skip over leading zeros in the
     * exponent. The function would leak the number of leading zeros, but it
     * would be much faster for small powers. Maybe we should provide that as
     * option, for situations that can tolerate that kind of side-channel
     * leakage?
     */
    template <typename F, typename BigInt>
    void exponentiate_restrict(F& __restrict res, const F& __restrict a, const BigInt& __restrict power) {
#ifdef RESIST_SIDE_CHANNELS
        F tmp;
#else
        bool found_one = false;
#endif
        res.copy(F::one);
        for (int i = BigInt::bits_value - 1; i != -1; i--) {
#ifdef RESIST_SIDE_CHANNELS
            res.square(res);
            if (power.bit(i)) {
                res.multiply(res, a);
            } else {
                tmp.multiply(res, a);
            }
#else
            if (found_one) {
                res.square(res);
            }
            if (power.bit(i)) {
                res.multiply(res, a);
                found_one = true;
            }
#endif
        }
    }

    template <typename F, typename BigInt>
    void exponentiate(F& res, const F& a, const BigInt& __restrict power) {
        F tmp;
        exponentiate_restrict<F, BigInt>(tmp, a, power);
        res.copy(tmp);
    }

    /*
     * We define these as separate functions for reason #2 above
     * (reason #1 does not apply here).
     */
    template <typename Fp>
    void fp_inverse(Fp& res, const Fp& a) {
        /* Algorithm below will not terminate for a = 0, so check if it is. */
        if (a.is_zero()) {
            res.set_zero();
            return;
        }

        Fp b;
        b.copy(Fp::r2_value);

        Fp c;
        c.set_zero();

        BigInt<Fp::bits_value> u = a.val;
        BigInt<Fp::bits_value> v = Fp::p_value;

        while (!u.is_one() && !v.is_one()) {
            while (u.is_even()) {
                u.template shift_right_in_word<1>(u);
                if (b.val.is_odd()) {
                    b.val.add(b.val, Fp::p_value);
                }
                b.val.template shift_right_in_word<1>(b.val);
            }
            while (v.is_even()) {
                v.template shift_right_in_word<1>(v);
                if (c.val.is_odd()) {
                    c.val.add(c.val, Fp::p_value);
                }
                c.val.template shift_right_in_word<1>(c.val);
            }
            if (BigInt<Fp::bits_value>::compare(v, u) == -1) {
                u.subtract(u, v);
                b.subtract(b, c);
            } else {
                v.subtract(v, u);
                c.subtract(c, b);
            }
        }

        if (u.is_one()) {
            res.copy(b);
        } else {
            res.copy(c);
        }
    }
}

#endif
