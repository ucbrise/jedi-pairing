/****************************************************************************
**
** Copyright (C) 2015 Stiftung Secure Information and
**                    Communication Technologies SIC and
**                    Graz University of Technology
** Contact: http://opensource.iaik.tugraz.at
**
**
** Commercial License Usage
** Licensees holding valid commercial licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and SIC. For further information
** contact us at http://opensource.iaik.tugraz.at.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** This software is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this software. If not, see http://www.gnu.org/licenses/.
**
**
****************************************************************************/

// NOTE: these tests are adapted from
// https://github.com/IAIK/pairings_in_c/blob/develop/framework/test/test_bigint.c

#include <stdio.h>
#include "core/bigint.hpp"

using embedded_pairing::core::BigInt;

bool passed = true;

int assert_true(bool result, const char* msg) {
    printf("%s: %s\n", msg, result ? "success" : "failure");
    passed = passed && result;
    return result ? 1 : 0;
}

template <int bits>
int assert_equal(const BigInt<bits>& a, const BigInt<bits>& b, const char* msg) {
    bool result = BigInt<bits>::equal(a, b);
    return assert_true(result, msg);
}

extern "C" {
    void run_bigint_tests(void);
}

void run_bigint_tests(void) {
    BigInt<256> var_tmp;
    BigInt<512> var_res;
    BigInt<256> var_res_small;

    {
        static const BigInt<256> var_a = {.std_words = {0xDD2201F8, 0x3060854B, 0x812712C8, 0xD9E3F220, 0x76DC58E5, 0x995D0C4A, 0x3DD3D846, 0xC3A474A2}};
        static const BigInt<256> var_b = {.std_words = {0xA041697E, 0xCB0EF7AB, 0xB367F31C, 0xD4EE6070, 0x4688DBA6, 0x19A654AD, 0x7CF5A363, 0x4CEB0DBD}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 141 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 128 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 131 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9D882303, 0x7B56E883, 0x599E1EEF, 0x3F19870B, 0xFD9998DB, 0x0918352C, 0x59F0B395, 0x0C3F2E09}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 1 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 2 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEAF714B8, 0x69893982, 0xE594B095, 0xC37EEB58, 0x01D05EDD, 0x3CB905F8, 0x1F29C9DA, 0x93B2F89E}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 3 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 4 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x879EBF2D, 0xE3187D4A, 0xA9C26C71, 0xDF024E5F, 0x5E57FF63, 0x03801264, 0x4EA86908, 0x6C2180FC}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 5 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 6 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7C993A71, 0x7E73CAA6, 0x28B0817F, 0xAF9C8652, 0xDB9ACDAF, 0xEBA0AC1A, 0x76525248, 0x38DEB573}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 7 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 8 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB45295CB, 0xC249B07C, 0x29078C75, 0x226F44E3, 0xE00B5E57, 0x311B5731, 0x2C61AC79, 0x2D12C4CA}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 9 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 10 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x80B99631, 0xAC585762, 0x38F7D740, 0x7CEFCF7F, 0xFDD27A44, 0x48DBE993, 0x897FF9EC, 0x957BD2FF}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 11 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 12 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x150BFB19, 0x2C044438, 0x24AABA11, 0xD45B7B53, 0x6410CE4B, 0x57AD0623, 0xACF6B6E1, 0x4D7C34C0}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 13 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 14 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x092B72F5, 0xA8C1C00E, 0x7FC8F5B7, 0x97813BAE, 0x6AAC634A, 0xB8FF49D0, 0x33EA89FF, 0x4778DAF8}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 15 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 16 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xDA8BE0E9, 0x78523BB5, 0x220E5701, 0x03D42273, 0x0AB86436, 0x7B75E125, 0xC6A406AD, 0x08842007}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 17 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 18 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x67A7A460, 0x67CE1E11, 0xA6EE0500, 0xADD2B889, 0x615DAE1A, 0xE14872F2, 0x8DF46496, 0x2A63541A}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 19 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 20 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7507E36D, 0x387EF4C0, 0xEB49319A, 0xFBBF6713, 0x33602687, 0xE17D7945, 0xB497B3EE, 0xDBD68C47}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 21 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 22 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2BDE1A15, 0x1F86D59F, 0x95300F89, 0xABA77A53, 0x652EEF99, 0xA6E48F83, 0xEEB85CF6, 0x5D3CACAA}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 23 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 24 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x962E85F5, 0x44607774, 0x8AB860F9, 0x4AB565CD, 0x8180DD67, 0x0EEC3B1D, 0xEF7B0D1A, 0x847BA8B0}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 25 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 26 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x268500F7, 0x44275D76, 0x75E1EB53, 0xBEDA521A, 0x358AD134, 0x2D443B5E, 0xF199528D, 0x3B457250}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 27 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 28 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2F408B26, 0xAFB0F75A, 0x46899D50, 0xBDC62C5C, 0xD4BAD59E, 0xC8506EDE, 0x300E7C9C, 0xFFA11589}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 29 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 30 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x69688E0F, 0x8B77BE4B, 0xB070455B, 0x532BA201, 0xD30D2599, 0xDB6BCF58, 0x6ED29911, 0x62D0EDF4}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_tmp.copy(var_a);
        assert_equal(var_tmp, var_a, "clear 31 ");
        var_tmp.clear();
        assert_equal(var_expected, var_tmp, "clear 32 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_expected = {.std_words = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 41 ");
        assert_true(carry == 1, "add 42 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 33 ");
        assert_true(carry == 0, "add 34 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 35 ");
        assert_true(carry == 0, "add 36 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 37 ");
        assert_true(carry == 0, "add 38 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 39 ");
        assert_true(carry == 0, "add 40 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 43 ");
        assert_true(carry == 1, "add 44 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 45 ");
        assert_true(carry == 1, "add 46 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 47 ");
        assert_true(carry == 0, "add 48 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x71197B85, 0xCF568B7D, 0xAA4F1E7D, 0x6054DBC3, 0x4DEB7AD6, 0x14F81F10, 0x70ABA3F0, 0x897306A3}};
        static const BigInt<256> var_b = {.std_words = {0x467A7CFF, 0xE913C320, 0xEFF99372, 0x180EDC63, 0x80984E0C, 0x55433574, 0x7E051E7F, 0xAF1104B1}};
        static const BigInt<256> var_expected = {.std_words = {0xB793F884, 0xB86A4E9D, 0x9A48B1F0, 0x7863B827, 0xCE83C8E2, 0x6A3B5484, 0xEEB0C26F, 0x38840B54}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 49 ");
        assert_true(carry == 1, "add 50 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCC45405E, 0x39B91409, 0x7E93F950, 0x81DBCBB2, 0x4E38DC4A, 0x35390F6E, 0xE7E0CD03, 0xA0E22D51}};
        static const BigInt<256> var_b = {.std_words = {0x4CE31732, 0x94C0D9BA, 0x1AD52124, 0xF87C9EDD, 0xBD5B1D80, 0x80E52294, 0x7BCE4DEB, 0x3EEE7201}};
        static const BigInt<256> var_expected = {.std_words = {0x19285790, 0xCE79EDC4, 0x99691A74, 0x7A586A8F, 0x0B93F9CB, 0xB61E3203, 0x63AF1AEE, 0xDFD09F53}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 51 ");
        assert_true(carry == 0, "add 52 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF20EF45D, 0xC20D6183, 0xCA600B38, 0xADC6D6C9, 0x7722131E, 0xB3C6828B, 0x0FFC9506, 0x007B84B9}};
        static const BigInt<256> var_b = {.std_words = {0x4E12FD41, 0xFFB8AEE0, 0x5A261357, 0x22C75D8E, 0x4BEB03C7, 0x81F0CE05, 0xFD50C968, 0x6ECC5FBF}};
        static const BigInt<256> var_expected = {.std_words = {0x4021F19E, 0xC1C61064, 0x24861E90, 0xD08E3458, 0xC30D16E5, 0x35B75090, 0x0D4D5E6F, 0x6F47E479}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 53 ");
        assert_true(carry == 0, "add 54 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD48CC96E, 0x7EA97AC4, 0xD9D75E21, 0xAF3DA8B8, 0xAA948ED4, 0x50FE161F, 0xA19AD901, 0xA631E1A2}};
        static const BigInt<256> var_b = {.std_words = {0x5CCC7540, 0xE1FF772D, 0x196E71C6, 0x0161A41B, 0x2B4DB588, 0xBCD5175A, 0xDDC8D473, 0xDA633A9A}};
        static const BigInt<256> var_expected = {.std_words = {0x31593EAE, 0x60A8F1F2, 0xF345CFE8, 0xB09F4CD3, 0xD5E2445C, 0x0DD32D79, 0x7F63AD75, 0x80951C3D}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 55 ");
        assert_true(carry == 1, "add 56 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA2B51DA7, 0xC3502F29, 0x33BD1BD6, 0x97F5295B, 0x07F441BA, 0x14397F1C, 0x953AEDC8, 0xD034661A}};
        static const BigInt<256> var_b = {.std_words = {0xC73C7BD0, 0x2EAFF58F, 0x00193B92, 0x44B4E643, 0x9D0926D8, 0xD8291F58, 0x341A8FA0, 0x618DF30F}};
        static const BigInt<256> var_expected = {.std_words = {0x69F19977, 0xF20024B9, 0x33D65768, 0xDCAA0F9E, 0xA4FD6892, 0xEC629E74, 0xC9557D68, 0x31C25929}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 57 ");
        assert_true(carry == 1, "add 58 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCE6DAB5C, 0x2587CAB3, 0xA009F826, 0xB0000145, 0xEF2FB831, 0x411B3B01, 0x26CA1422, 0xFABBC18D}};
        static const BigInt<256> var_b = {.std_words = {0x20055C46, 0x1C4826CA, 0xF70F7773, 0xD7EFEA0D, 0x243BF18B, 0xB9F4580D, 0x5C61EC83, 0x1E138820}};
        static const BigInt<256> var_expected = {.std_words = {0xEE7307A2, 0x41CFF17D, 0x97196F99, 0x87EFEB53, 0x136BA9BD, 0xFB0F930F, 0x832C00A5, 0x18CF49AD}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 59 ");
        assert_true(carry == 1, "add 60 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0998E3AC, 0x7ADF0310, 0x2B7A2D99, 0x889E1F68, 0x04D20A2E, 0x5EE43FF9, 0xCB37403E, 0xE1D74237}};
        static const BigInt<256> var_b = {.std_words = {0x384D063D, 0x1E03AF86, 0x28484C5C, 0xE7D7C4E1, 0x7F9E21BA, 0x84010F40, 0xED827410, 0x6E80DF39}};
        static const BigInt<256> var_expected = {.std_words = {0x41E5E9E9, 0x98E2B296, 0x53C279F5, 0x7075E449, 0x84702BE9, 0xE2E54F39, 0xB8B9B44E, 0x50582171}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 61 ");
        assert_true(carry == 1, "add 62 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x4325690B, 0xD74B21AF, 0x1C20F37B, 0xEB0B6BC3, 0x260EBD58, 0x30BF95C0, 0x3E020CD9, 0x8342C2F8}};
        static const BigInt<256> var_b = {.std_words = {0x21D3F551, 0xEB1FF8D8, 0xFB521D8D, 0xE1956518, 0xB0A25EF8, 0x9D2E58C9, 0xC0BBC5DF, 0xF0F1FE18}};
        static const BigInt<256> var_expected = {.std_words = {0x64F95E5C, 0xC26B1A87, 0x17731109, 0xCCA0D0DC, 0xD6B11C51, 0xCDEDEE89, 0xFEBDD2B8, 0x7434C110}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 63 ");
        assert_true(carry == 1, "add 64 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xAE24B1A7, 0x916D4D71, 0xFCF07A8F, 0xE7527546, 0x77D27AA4, 0xBB11E966, 0x77C8059A, 0x1C2F5F02}};
        static const BigInt<256> var_b = {.std_words = {0x2AFBC5F8, 0x7735FD3C, 0x1AEEA767, 0x7288BFCE, 0xF8787D41, 0xABBD839B, 0xEE30DB21, 0x80E58F9D}};
        static const BigInt<256> var_expected = {.std_words = {0xD920779F, 0x08A34AAD, 0x17DF21F7, 0x59DB3515, 0x704AF7E6, 0x66CF6D02, 0x65F8E0BC, 0x9D14EEA0}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 65 ");
        assert_true(carry == 0, "add 66 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xBAD3C6BA, 0x3CE52191, 0x935673A6, 0xC81A4B57, 0x57D7BB4D, 0x44CD0F5A, 0xB1D93490, 0x291A10E2}};
        static const BigInt<256> var_b = {.std_words = {0xE6DF6797, 0xF781D16B, 0x6D932889, 0x87137E09, 0xD82476A1, 0x91A3F879, 0xD17F172B, 0x3A0ABBCC}};
        static const BigInt<256> var_expected = {.std_words = {0xA1B32E51, 0x3466F2FD, 0x00E99C30, 0x4F2DC961, 0x2FFC31EF, 0xD67107D4, 0x83584BBB, 0x6324CCAF}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 67 ");
        assert_true(carry == 0, "add 68 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x19AE330E, 0xAEA265C6, 0xECBE0CEB, 0x1C7855A7, 0x67AF4A8A, 0x51BE825C, 0x63C5E6E0, 0x689907D9}};
        static const BigInt<256> var_b = {.std_words = {0x2562FC5B, 0xE03AD899, 0x1D0982F4, 0x4D705176, 0x118CBC08, 0x76D888A7, 0x014E13DA, 0x7C105780}};
        static const BigInt<256> var_expected = {.std_words = {0x3F112F69, 0x8EDD3E5F, 0x09C78FE0, 0x69E8A71E, 0x793C0692, 0xC8970B03, 0x6513FABA, 0xE4A95F59}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 69 ");
        assert_true(carry == 0, "add 70 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xBC7D0B4D, 0xFC34FFD4, 0x4F2C83B0, 0xB0BC4F44, 0x89D7AF68, 0xA7DCCA4C, 0x47EBBF02, 0xD52BED93}};
        static const BigInt<256> var_b = {.std_words = {0xF738527D, 0xE7DCB0F3, 0x95F16855, 0x317DCE57, 0xA486FDE7, 0xBDA73810, 0x57D92F4E, 0xE3796B7F}};
        static const BigInt<256> var_expected = {.std_words = {0xB3B55DCA, 0xE411B0C8, 0xE51DEC06, 0xE23A1D9B, 0x2E5EAD4F, 0x6584025D, 0x9FC4EE51, 0xB8A55912}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 71 ");
        assert_true(carry == 1, "add 72 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD36A1CF0, 0x7A1A1BFD, 0x45C52BFA, 0x90475112, 0xDDC680A0, 0x499BE2E2, 0x560B101E, 0xAD09EAA2}};
        static const BigInt<256> var_b = {.std_words = {0xB00108D7, 0x027CD76E, 0x7B5B93A5, 0xE08DE268, 0xD2EE3F75, 0x0D007AB3, 0xEC87EDA7, 0x4C6907FD}};
        static const BigInt<256> var_expected = {.std_words = {0x836B25C7, 0x7C96F36C, 0xC120BF9F, 0x70D5337A, 0xB0B4C016, 0x569C5D96, 0x4292FDC5, 0xF972F2A0}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 73 ");
        assert_true(carry == 0, "add 74 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD00B43D6, 0xBF108601, 0x97640621, 0x0A55EB1B, 0xC5FE9254, 0x7F388BC8, 0xC8D56A6B, 0x6EF4894E}};
        static const BigInt<256> var_b = {.std_words = {0xDE4F5212, 0x6513F942, 0xBA51ECBC, 0x483BDBC4, 0x1CB169BB, 0x49C3DB53, 0x1A7806CC, 0xD4726CBA}};
        static const BigInt<256> var_expected = {.std_words = {0xAE5A95E8, 0x24247F44, 0x51B5F2DE, 0x5291C6E0, 0xE2AFFC0F, 0xC8FC671B, 0xE34D7137, 0x4366F608}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 75 ");
        assert_true(carry == 1, "add 76 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x6475E2D9, 0x9D643BB9, 0x4E29D340, 0xAACE5A65, 0xE11A1308, 0xCB0D96B1, 0x187B84A9, 0xD40670A6}};
        static const BigInt<256> var_b = {.std_words = {0x53BD65CC, 0x85D5FBA0, 0x7B6BCB95, 0x94330221, 0x42DC28D5, 0x98162DB1, 0x79104D62, 0xD76B8D49}};
        static const BigInt<256> var_expected = {.std_words = {0xB83348A5, 0x233A3759, 0xC9959ED6, 0x3F015C86, 0x23F63BDE, 0x6323C463, 0x918BD20C, 0xAB71FDEF}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 77 ");
        assert_true(carry == 1, "add 78 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7F4A80F4, 0x2C422761, 0xB206AC55, 0x3E1BCE2F, 0x12E17F47, 0xF4DF2159, 0xFD3B5203, 0xDC84DFE6}};
        static const BigInt<256> var_b = {.std_words = {0x21FA846B, 0x177CBB7C, 0x265C304E, 0x330ACDE4, 0x46B140F4, 0x5DB214D2, 0xE38F4E89, 0xF43AE12C}};
        static const BigInt<256> var_expected = {.std_words = {0xA145055F, 0x43BEE2DD, 0xD862DCA3, 0x71269C13, 0x5992C03B, 0x5291362B, 0xE0CAA08D, 0xD0BFC113}};
        int carry = var_res_small.add(var_a, var_b);
        assert_equal(var_expected, var_res_small, "add 79 ");
        assert_true(carry == 1, "add 80 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 81 ");
        assert_true(carry == 0, "subtract 82 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 83 ");
        assert_true(carry == 0, "subtract 84 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 85 ");
        assert_true(carry, "subtract 86 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 87 ");
        assert_true(carry == 0, "subtract 88 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 89 ");
        assert_true(carry == 0, "subtract 90 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_expected = {.std_words = {0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 91 ");
        assert_true(carry, "subtract 92 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_expected = {.std_words = {0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 93 ");
        assert_true(carry == 0, "subtract 94 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x53CC84C1, 0xBF041D23, 0x4E542233, 0xD2EEBED9, 0x7A5189C6, 0xFF2ECC88, 0x70F96EFF, 0xC4AB1892}};
        static const BigInt<256> var_b = {.std_words = {0x97DCB293, 0x1198797E, 0x6583022F, 0xD007A1ED, 0x6AB33A16, 0x3E321C22, 0x6F9DB9F7, 0x06A889D1}};
        static const BigInt<256> var_expected = {.std_words = {0xBBEFD22E, 0xAD6BA3A4, 0xE8D12004, 0x02E71CEB, 0x0F9E4FB0, 0xC0FCB066, 0x015BB508, 0xBE028EC1}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 95 ");
        assert_true(carry == 0, "subtract 96 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x51EA1E71, 0xEC860187, 0xEA5DE0BD, 0xB51A60C9, 0x79B6D3F3, 0x3086D68E, 0xACC4C351, 0x078289DA}};
        static const BigInt<256> var_b = {.std_words = {0x4871086C, 0xA6E10171, 0x217D5442, 0x5AFA2A0B, 0x2DB87B87, 0x20652F69, 0x78D88884, 0x2B2CCEA0}};
        static const BigInt<256> var_expected = {.std_words = {0x09791605, 0x45A50016, 0xC8E08C7B, 0x5A2036BE, 0x4BFE586C, 0x1021A725, 0x33EC3ACD, 0xDC55BB3A}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 97 ");
        assert_true(carry, "subtract 98 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x29524C7C, 0x887229C3, 0x8FF3CE10, 0x715D1F0E, 0xB0B49E43, 0x0DCC3FC8, 0x286F74A8, 0x65A7D23A}};
        static const BigInt<256> var_b = {.std_words = {0x040BAF25, 0x4D8882C1, 0x81B1AB41, 0xFD044B81, 0x51F7BC95, 0x289D8FE1, 0x9668F14E, 0xBFC1EAA5}};
        static const BigInt<256> var_expected = {.std_words = {0x25469D57, 0x3AE9A702, 0x0E4222CF, 0x7458D38D, 0x5EBCE1AD, 0xE52EAFE7, 0x92068359, 0xA5E5E794}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 99 ");
        assert_true(carry, "subtract 100 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCD7F05AB, 0xA790EB20, 0x86F9BE76, 0xD5323BA6, 0x015B50B2, 0x5A92D123, 0x9E1A10CD, 0xD824A058}};
        static const BigInt<256> var_b = {.std_words = {0xDC527E75, 0xBA8218E6, 0xF1E44BE5, 0x2670941C, 0xD71AE912, 0xBBFF3AF1, 0xA28D15FF, 0x61B43285}};
        static const BigInt<256> var_expected = {.std_words = {0xF12C8736, 0xED0ED239, 0x95157290, 0xAEC1A789, 0x2A4067A0, 0x9E939631, 0xFB8CFACD, 0x76706DD2}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 101 ");
        assert_true(carry == 0, "subtract 102 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x6ECD8D3D, 0x9F1967EA, 0x58F89661, 0xEEA36C95, 0x8C32E43F, 0x1C6621C3, 0x07C905B3, 0x9F3C568F}};
        static const BigInt<256> var_b = {.std_words = {0x21583EF1, 0xE3DE0FC0, 0x18C886DD, 0x827961A6, 0x004F5D89, 0x7ED5C74B, 0xB62F7BD8, 0xED7087C1}};
        static const BigInt<256> var_expected = {.std_words = {0x4D754E4C, 0xBB3B582A, 0x40300F83, 0x6C2A0AEF, 0x8BE386B6, 0x9D905A78, 0x519989DA, 0xB1CBCECD}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 103 ");
        assert_true(carry, "subtract 104 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7C83E749, 0x05057E96, 0xCEAC04C8, 0x0817A539, 0xB34E3E65, 0x991F861E, 0x9CEC5C4C, 0x363A92BF}};
        static const BigInt<256> var_b = {.std_words = {0x65A08D81, 0xFB11D84E, 0xDF870FFF, 0xFE237BC5, 0x4C528E42, 0x56DAB381, 0x2A6F4697, 0x7F55238D}};
        static const BigInt<256> var_expected = {.std_words = {0x16E359C8, 0x09F3A648, 0xEF24F4C8, 0x09F42973, 0x66FBB022, 0x4244D29D, 0x727D15B5, 0xB6E56F32}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 105 ");
        assert_true(carry, "subtract 106 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA9E86B9E, 0xAE590328, 0xF197B292, 0xB11FE08A, 0x165D62C4, 0x55320151, 0xD5F7B13D, 0x5B427F40}};
        static const BigInt<256> var_b = {.std_words = {0x77376B59, 0x7948AC48, 0x705D526B, 0xC7075598, 0x7E851181, 0x688D2742, 0x97343851, 0x7581B8A2}};
        static const BigInt<256> var_expected = {.std_words = {0x32B10045, 0x351056E0, 0x813A6027, 0xEA188AF2, 0x97D85142, 0xECA4DA0E, 0x3EC378EB, 0xE5C0C69E}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 107 ");
        assert_true(carry, "subtract 108 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xE55187BA, 0xAE7D1DF5, 0x0A8F0102, 0xB64E0933, 0x97B58E94, 0x16FD1B71, 0x6CED76CA, 0x0A23FF0F}};
        static const BigInt<256> var_b = {.std_words = {0x6ABF6424, 0x11B6EF6D, 0x331ED0BD, 0x4A22DD95, 0x96FB098F, 0x19812DD4, 0xD6C070D3, 0x6CA5E3E3}};
        static const BigInt<256> var_expected = {.std_words = {0x7A922396, 0x9CC62E88, 0xD7703045, 0x6C2B2B9D, 0x00BA8505, 0xFD7BED9D, 0x962D05F6, 0x9D7E1B2B}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 109 ");
        assert_true(carry, "subtract 110 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x623299AE, 0x5B86DC4B, 0xA24B4635, 0x2302F6AA, 0x556A3B8B, 0xE019B91B, 0x5AF07792, 0x8023A79E}};
        static const BigInt<256> var_b = {.std_words = {0x8E80685C, 0xB8E53DAC, 0xD2CB7D87, 0x34A6DF81, 0xD489F981, 0x0EAB5D8C, 0x013DF635, 0x41D3F2B9}};
        static const BigInt<256> var_expected = {.std_words = {0xD3B23152, 0xA2A19E9E, 0xCF7FC8AD, 0xEE5C1728, 0x80E04209, 0xD16E5B8E, 0x59B2815D, 0x3E4FB4E5}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 111 ");
        assert_true(carry == 0, "subtract 112 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x912BF8F3, 0x498804A9, 0x82FB8A3C, 0x463573C9, 0xB457FD42, 0xF9ADD995, 0xD8D3A3F9, 0x3BD490D4}};
        static const BigInt<256> var_b = {.std_words = {0x74793BF8, 0xA3092F66, 0x352428A1, 0x73CBFE81, 0xBAD7F5D4, 0x2CB4FC43, 0x704AFF9D, 0x104E0076}};
        static const BigInt<256> var_expected = {.std_words = {0x1CB2BCFB, 0xA67ED543, 0x4DD7619A, 0xD2697548, 0xF980076D, 0xCCF8DD51, 0x6888A45C, 0x2B86905E}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 113 ");
        assert_true(carry == 0, "subtract 114 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x221D1A8E, 0x4FE70B76, 0xB3D0D45D, 0xAB506771, 0x52344D61, 0xE5B9562A, 0x5EAB1853, 0xF7DEFE2B}};
        static const BigInt<256> var_b = {.std_words = {0xED6E93E3, 0x484BD074, 0x8631DB1D, 0x329F3EA0, 0x096F413A, 0x98488F16, 0xBC920168, 0x385A612D}};
        static const BigInt<256> var_expected = {.std_words = {0x34AE86AB, 0x079B3B01, 0x2D9EF940, 0x78B128D1, 0x48C50C27, 0x4D70C714, 0xA21916EB, 0xBF849CFD}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 115 ");
        assert_true(carry == 0, "subtract 116 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0735E005, 0x80A64D83, 0x7E91ED76, 0x20FA074C, 0x12A132FC, 0x6A698EA8, 0xA75A7428, 0xB1D6D5FE}};
        static const BigInt<256> var_b = {.std_words = {0x0AFCD4F1, 0x5B1BD0B7, 0x2EDA4DE6, 0xE0D32448, 0xC3CB4845, 0xB667E1EA, 0xBF578432, 0x540D69CF}};
        static const BigInt<256> var_expected = {.std_words = {0xFC390B14, 0x258A7CCB, 0x4FB79F90, 0x4026E304, 0x4ED5EAB6, 0xB401ACBD, 0xE802EFF5, 0x5DC96C2E}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 117 ");
        assert_true(carry == 0, "subtract 118 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x71FF0610, 0x31B86FB3, 0x6C28B1A4, 0xB1E423BC, 0x1539D300, 0x8C630529, 0xAA256936, 0xA607E963}};
        static const BigInt<256> var_b = {.std_words = {0x1CA2753C, 0xD1815E49, 0xD5705146, 0x28916C8B, 0x276C03CE, 0x2DB4818C, 0x9003B782, 0x421E7F71}};
        static const BigInt<256> var_expected = {.std_words = {0x555C90D4, 0x6037116A, 0x96B8605D, 0x8952B730, 0xEDCDCF32, 0x5EAE839C, 0x1A21B1B4, 0x63E969F2}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 119 ");
        assert_true(carry == 0, "subtract 120 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD076BAEF, 0xF94DFD8C, 0x4634DF98, 0xACA08077, 0xBAA1E59B, 0x901AFC7C, 0xA04096F7, 0x54471B39}};
        static const BigInt<256> var_b = {.std_words = {0xB5D8011E, 0xDF6DC1AA, 0x644445F5, 0xF9434E3B, 0xB6E0B82E, 0xE1C3B05A, 0x8AB8CBFB, 0x1FB58A0E}};
        static const BigInt<256> var_expected = {.std_words = {0x1A9EB9D1, 0x19E03BE2, 0xE1F099A3, 0xB35D323B, 0x03C12D6C, 0xAE574C22, 0x1587CAFB, 0x3491912B}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 121 ");
        assert_true(carry == 0, "subtract 122 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD6134EE6, 0xAB2835A7, 0x15987047, 0x9E6B4C73, 0xA59A08E5, 0xFC1BF8ED, 0x0460A4D6, 0x77C45337}};
        static const BigInt<256> var_b = {.std_words = {0xA41DC73A, 0xFA059D7E, 0x05308E62, 0x7F6E5B23, 0x33DC29BD, 0xF66FC4D1, 0x46E11562, 0x483BB136}};
        static const BigInt<256> var_expected = {.std_words = {0x31F587AC, 0xB1229829, 0x1067E1E4, 0x1EFCF150, 0x71BDDF28, 0x05AC341C, 0xBD7F8F74, 0x2F88A200}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 123 ");
        assert_true(carry == 0, "subtract 124 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x74DD1841, 0x5DE80B27, 0x230B71D4, 0x5300A410, 0xB40DFE4D, 0x95604132, 0x8D48A660, 0x0DD7462D}};
        static const BigInt<256> var_b = {.std_words = {0xFC042248, 0xD8F7EFA5, 0x212B124F, 0x2678EEF2, 0x9E431D20, 0xD324FF73, 0x9BC0ECE2, 0x592B696C}};
        static const BigInt<256> var_expected = {.std_words = {0x78D8F5F9, 0x84F01B81, 0x01E05F84, 0x2C87B51E, 0x15CAE12D, 0xC23B41BF, 0xF187B97D, 0xB4ABDCC0}};
        int carry = var_res_small.subtract(var_a, var_b);
        assert_equal(var_expected, var_res_small, "subtract 125 ");
        assert_true(carry, "subtract 126 (carry)");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 127 ");
    }

    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 129 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 130 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 132 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xDA7875D6, 0x635C62C1, 0xF7A85CEB, 0xD9662CB6, 0x0A1FCA96, 0x5F9C53BB, 0x355FBD10, 0x52D012BE}};
        static const BigInt<256> var_b = {.std_words = {0xDA7875D6, 0x635C62C1, 0xF7A85CEB, 0xD9662CB6, 0x0A1FCA96, 0x5F9C53BB, 0x355FBD10, 0x52D012BE}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 133 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0D497083, 0x6CC8C3D4, 0x60D9B7FC, 0x9D7D2EA2, 0x373E5162, 0x1B32DBD6, 0xA401525A, 0x31E1E02B}};
        static const BigInt<256> var_b = {.std_words = {0x0D497083, 0x6CC8C3D4, 0x60D9B7FC, 0x9D7D2EA2, 0x373E5162, 0x1B32DBD6, 0xA401525A, 0x31E1E02B}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 134 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7A39E602, 0x53D36FF7, 0x5B8101E9, 0x7CC4C043, 0x073DB647, 0x9F8E43C3, 0x3539028E, 0xC3CAB040}};
        static const BigInt<256> var_b = {.std_words = {0x7A39E602, 0x53D36FF7, 0x5B8101E9, 0x7CC4C043, 0x073DB647, 0x9F8E43C3, 0x3539028E, 0xC3CAB040}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 135 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x68DAA609, 0xED2391F3, 0xAB1AEA7C, 0xD020A75F, 0x8145D0E3, 0xB51ACAD9, 0xB9475C8F, 0xEB69B9D9}};
        static const BigInt<256> var_b = {.std_words = {0x68DAA609, 0xED2391F3, 0xAB1AEA7C, 0xD020A75F, 0x8145D0E3, 0xB51ACAD9, 0xB9475C8F, 0xEB69B9D9}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 136 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x04315D77, 0x026B6082, 0x5828E580, 0xCA2B340D, 0x4D3038F2, 0xDB5118BE, 0x062CB174, 0x1E7A399D}};
        static const BigInt<256> var_b = {.std_words = {0x04315D77, 0x026B6082, 0x5828E580, 0xCA2B340D, 0x4D3038F2, 0xDB5118BE, 0x062CB174, 0x1E7A399D}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 137 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xDEEF8B80, 0xCF2D58E2, 0x2C9B1FE7, 0xEC587453, 0x3B35AA8A, 0xC4E4674B, 0x73BE65A0, 0xE5531516}};
        static const BigInt<256> var_b = {.std_words = {0xDEEF8B80, 0xCF2D58E2, 0x2C9B1FE7, 0xEC587453, 0x3B35AA8A, 0xC4E4674B, 0x73BE65A0, 0xE5531516}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 138 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x6A3FA869, 0x85602723, 0x37462EC7, 0x8F6C2749, 0xBC2BBDB9, 0xD7AB1814, 0x60DD9A03, 0x5EFBFD44}};
        static const BigInt<256> var_b = {.std_words = {0x6A3FA869, 0x85602723, 0x37462EC7, 0x8F6C2749, 0xBC2BBDB9, 0xD7AB1814, 0x60DD9A03, 0x5EFBFD44}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 139 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x811695C2, 0xC8D06C72, 0x4C636680, 0x5E4202C5, 0x675B11D4, 0xAE692282, 0xACA9FE17, 0xBC7EFB30}};
        static const BigInt<256> var_b = {.std_words = {0x811695C2, 0xC8D06C72, 0x4C636680, 0x5E4202C5, 0x675B11D4, 0xAE692282, 0xACA9FE17, 0xBC7EFB30}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 0, "compare 140 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCD87C1D0, 0x99D54255, 0x004DC615, 0xF54BA4CE, 0xDB79587B, 0x657371FC, 0xD603C698, 0xC7D5F99D}};
        static const BigInt<256> var_b = {.std_words = {0xCEDA06FB, 0x0F5127B4, 0x4B19B644, 0x39352C18, 0x591E6708, 0xE809D6E3, 0x3CC639A5, 0xB48B947D}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 142 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xED183B6F, 0x953B9E3C, 0xBBFBF5F5, 0x6F8C1076, 0x8CD5B927, 0xC094A552, 0xA3653B92, 0x29C76414}};
        static const BigInt<256> var_b = {.std_words = {0xDAD18D71, 0x08B81EE9, 0x3CF5EFE3, 0xBB8107A1, 0x6122E414, 0x41C8FD34, 0x85084A18, 0x4F13DC2C}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 143 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2B8FB37E, 0x396CEE12, 0xFCCCBB17, 0x158AF9A5, 0x6B6B86EE, 0x705403CF, 0x5F7F10C3, 0xE55A705C}};
        static const BigInt<256> var_b = {.std_words = {0xD7ACADAD, 0x6B6B8B08, 0xEF14D090, 0xC8A5AD43, 0x5F4B01DC, 0x89271A41, 0x31010784, 0xBCC6E8D7}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 144 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xBBC18434, 0xD9F0789E, 0x4C3E1FFB, 0xF3F647AE, 0x9871126B, 0x7A80F3A0, 0x01F8DFCB, 0x39ECF737}};
        static const BigInt<256> var_b = {.std_words = {0x1598B7E5, 0x2EEAF875, 0x0EBE12AF, 0x0BA894A2, 0x9412FD02, 0x65D15B1E, 0x58DD1173, 0xD64B7DCC}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 145 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0CB660B2, 0x0A527CDC, 0x75411673, 0x57225938, 0x74E81F9D, 0x2272F2DD, 0xC32610B2, 0xA01F08CE}};
        static const BigInt<256> var_b = {.std_words = {0x257654FB, 0x845AD4F5, 0x82F2A4FA, 0x739425D0, 0x80C31A4D, 0xBA22358F, 0x5342052A, 0xBA797556}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 146 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCFAFB9C1, 0xA3676E5A, 0x7ECC0AEB, 0xCEC860CE, 0xA1AAE584, 0xED5D8946, 0x1EA31F87, 0xD9B2C38A}};
        static const BigInt<256> var_b = {.std_words = {0xD9EFDE95, 0xE4D92472, 0x73004C42, 0x2B4C8892, 0xE68B7B6B, 0xAD7B2DCF, 0xBCDDC395, 0xC72875C9}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 147 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF6404E79, 0xB7A86E9B, 0xB169E458, 0x24E4DE3E, 0xFF7CFA0E, 0xA1A33B7C, 0xCAD435BC, 0xE14C1C02}};
        static const BigInt<256> var_b = {.std_words = {0x408461C7, 0x02CDF79D, 0x4B12515B, 0xA2550372, 0xC58B5BB5, 0xA38F287B, 0x6AF58AAA, 0x9902EB93}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 148 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB259D99D, 0x9C7BECFE, 0x98C79504, 0x667B2909, 0xB01E2411, 0x431E68CD, 0xC183F7BA, 0xF44D5F32}};
        static const BigInt<256> var_b = {.std_words = {0xAD98382D, 0xD32F818C, 0xB2BE3097, 0x84ACEF5E, 0x5FE5B2A9, 0x41B5215A, 0x78F7C8EC, 0x0C526758}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 149 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x7458E6CE, 0xE78581DD, 0xFA482E8E, 0xE3720A40, 0x14590A59, 0x16741EFC, 0x3C689F9C, 0x8F9F96C3}};
        static const BigInt<256> var_b = {.std_words = {0xB08858BD, 0x8CE5EF90, 0x92984E44, 0xBE9140FC, 0x35CD3A5B, 0x6C365B0B, 0x3F0AB81C, 0x3ED3464A}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 150 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEC19C9D0, 0x6CFCFFD0, 0xE1946FDB, 0x255C718F, 0xCD0FCE0D, 0xA166E8A4, 0xB4BA5A18, 0x6F84BD20}};
        static const BigInt<256> var_b = {.std_words = {0x19B637B1, 0xA308F6FB, 0x13BFAC02, 0x7D5B9FDB, 0x089AD627, 0x49A001DF, 0x569CBC3D, 0x8C83B14A}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 151 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0C09BA84, 0x41F3B45C, 0x9726E7D5, 0xFC453952, 0xBA5084E5, 0xA922872A, 0xE2C3E901, 0x9268C987}};
        static const BigInt<256> var_b = {.std_words = {0xFB985C3F, 0xCC3A058C, 0x9F6DA7F5, 0x2E451B38, 0xD9D4605C, 0x3D13435E, 0x98F48772, 0x9371ED82}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 152 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x042F1660, 0xBBADDE6A, 0xA3DD8B22, 0x738C02E5, 0xFF6395EF, 0x3290A44B, 0xBE6C84F1, 0x34B1866D}};
        static const BigInt<256> var_b = {.std_words = {0xA7CF8F14, 0xFCF43EA5, 0xDE8BB41B, 0x7E3F6DFC, 0xE948DCA5, 0xEC92DA47, 0x1DC2FE66, 0x308D0579}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 153 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x4643C373, 0x6FEE5654, 0xCF8DDF3B, 0xD7A820A3, 0xFADBFFF4, 0x82A278C7, 0x82CE02EE, 0xD38C49D2}};
        static const BigInt<256> var_b = {.std_words = {0xAC2EB2BD, 0x68D718A6, 0xBA3D2755, 0x5AC0CF21, 0xB9130971, 0x3D560F06, 0x3EACE340, 0x7F77C4DB}};
        assert_true(BigInt<256>::compare(var_a, var_b) == 1, "compare 154 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x83BBB754, 0x31477167, 0x258F9497, 0xB6019C3A, 0x4EA57FAF, 0x1DA862B6, 0xA7C24932, 0x2AC37264}};
        static const BigInt<256> var_b = {.std_words = {0xDCD03673, 0x85F9B4ED, 0x5B73F7E2, 0xEF926AB4, 0x09B55D99, 0x541728E3, 0x95E24550, 0xDE520383}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 155 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xACDBA676, 0x17690D23, 0xEC4DB7C0, 0xDDBA4744, 0xDC169958, 0xC89A767B, 0xE572FB66, 0x3885C88D}};
        static const BigInt<256> var_b = {.std_words = {0x492741F7, 0x093AEE68, 0x2B798D66, 0xABA7520A, 0xDC1E6408, 0x95635281, 0xFAACB3F8, 0xEA924C61}};
        assert_true(BigInt<256>::compare(var_a, var_b) == -1, "compare 156 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 157 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 158 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 159 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 160 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 161 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        BigInt<512> var_expected = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 162 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 163 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 164 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF1C5D0C9, 0x7574DD9A, 0xAFDA5B8F, 0x5885EB4C, 0xC3018851, 0x896FFE73, 0x37E96BE9, 0x3A3DA3C8}};
        static const BigInt<256> var_b = {.std_words = {0x43096777, 0xE88E18BB, 0xD28791AB, 0x39E41DFA, 0x71C57A26, 0xA7EBFD5A, 0x86FB308C, 0x80CCD263}};
        BigInt<512> var_expected = {.std_words = {0xEC05EC6F, 0x14C5FAB8, 0xFBB51619, 0xEE372BCF, 0x0BB1184A, 0x5F0CB16D, 0x3B13BD8C, 0x14117CC7, 0x52AADA43, 0xEBFBA5F8, 0x5B86166F, 0x70E72CB4, 0x8246E26D, 0xCDCDD4EA, 0xD4674177, 0x1D4D6ADF}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 165 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xC38AF6AC, 0xE148E0B9, 0x357ACFE6, 0x756F81BC, 0x66C112E5, 0xA566EFC9, 0xD49FD9F8, 0xAC5EEED9}};
        static const BigInt<256> var_b = {.std_words = {0x5AC416A3, 0x57557557, 0x3A54BFC4, 0x88F30A1E, 0x4AAFF93D, 0x6DD3AB50, 0x92F6F110, 0xBD85BB7D}};
        BigInt<512> var_expected = {.std_words = {0xC65DD784, 0x63C20EA6, 0xDD82EE53, 0x31ED914D, 0x83776F08, 0xB5A0D39F, 0x86476FEC, 0x5CBBB5AE, 0xC755F386, 0x8A436315, 0xB73BB59B, 0xB6BB6519, 0x58F0DBFE, 0x95E368BB, 0xCEEDA368, 0x7F9C21E6}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 166 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD5387284, 0x30D50F58, 0x89354EA3, 0xC1B48748, 0x664B4164, 0xA05B530E, 0x3611EAE2, 0x4B36FDCC}};
        static const BigInt<256> var_b = {.std_words = {0x612CA167, 0xCBA15B20, 0x8C9FBD44, 0xC315BD70, 0x2885BB31, 0x0E023289, 0xB88ED92A, 0xFE05BE5B}};
        BigInt<512> var_expected = {.std_words = {0xFC6B171C, 0x5936506D, 0xA3029E12, 0x72E9D7CD, 0x86BFF8E6, 0xE3C71002, 0xC0D60244, 0x1DAE68FC, 0x2244EDD1, 0xEF5645F1, 0xB94FFAC5, 0xD21FB717, 0x1D5817E8, 0x7CA2B305, 0x55C61BD8, 0x4AA23FD1}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 167 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x15ED7287, 0x77674358, 0xF2693CA0, 0x088E66DE, 0xA33FF81E, 0x3F15A680, 0x15486A88, 0x14BA33CE}};
        static const BigInt<256> var_b = {.std_words = {0x69ABE702, 0xF98F1461, 0x30C7F99B, 0x59F08BD0, 0x0CA20A28, 0xED717229, 0xD00CBCA1, 0xDF25167D}};
        BigInt<512> var_expected = {.std_words = {0x4D5FB60E, 0x5DBBFD35, 0x57B6A274, 0x61F4155B, 0x6CC21C9F, 0x129444B4, 0x8AB87026, 0xA8E1F3DA, 0xF25A06C6, 0x6F08CBDB, 0xA0B5A73B, 0xED4DAA55, 0xF0AEA0AF, 0x6B7C07B2, 0x318A7BD0, 0x121133DC}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 168 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB7E25C94, 0x0BFD4543, 0xFB58E4FF, 0x5701EA32, 0x3EF877F9, 0x88952628, 0x6C6F53D3, 0x45598341}};
        static const BigInt<256> var_b = {.std_words = {0xC151AE5D, 0xD7926B37, 0xCF5487E4, 0xF65D6736, 0x3723F20A, 0xB18086A8, 0xF3A1653D, 0x3E1FCBAE}};
        BigInt<512> var_expected = {.std_words = {0x86FC39C4, 0xAEE0C6CC, 0x7814F139, 0xD69A782E, 0xF64388BE, 0xEE81E01D, 0x44F47A32, 0xA0E3891B, 0x1E2037F2, 0x81B23A4E, 0xEE3112B3, 0x85A6DF29, 0x071B1810, 0x0A1B0A53, 0x1D1ADF8C, 0x10D44ACE}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 169 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2A834D1D, 0x80922015, 0x6BB8B71D, 0xFCB1CF63, 0x9999BF9F, 0xBF691C24, 0x726213F7, 0x5ACCBBB1}};
        static const BigInt<256> var_b = {.std_words = {0xFBE591DE, 0x99C4F2C1, 0x538E03A5, 0x873E4FAD, 0x2AF8F2FE, 0x3D3F5EC5, 0x7AF764F0, 0x395D4A26}};
        BigInt<512> var_expected = {.std_words = {0xA67B4C26, 0x4198205B, 0x29130C07, 0xF3A27968, 0xC30C1D8B, 0x0CACCD2C, 0x7D30AEFE, 0x381A357C, 0xF1A99D1C, 0x9E10BBEB, 0xFEDA7653, 0x513AA758, 0xA0DF0EF9, 0x96A62875, 0x8630DC43, 0x1458AC77}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 170 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2076C37D, 0xAB739831, 0x4D4215D4, 0x84B06858, 0x5422D497, 0x69FA10D8, 0xA13C1994, 0x10E5AF75}};
        static const BigInt<256> var_b = {.std_words = {0xE9F4A126, 0xB436FBA7, 0xE4057D53, 0x39475F57, 0xA6F21C31, 0xB7C1D362, 0xFFBE998A, 0x2B4C56B8}};
        BigInt<512> var_expected = {.std_words = {0x9AB6A18E, 0xAAC19B5F, 0xE380D4FF, 0xB4739177, 0x1037FE4B, 0x9F61B800, 0x1BC4BD99, 0x9050701E, 0xBFC7EEE0, 0xBBBA045C, 0x1567E673, 0x735FB23B, 0x5BA665CB, 0x6C5E1BBD, 0x37E9F53A, 0x02DB9E62}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 171 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x8AB16A4A, 0xA38BE1B4, 0xE84492FE, 0xBB4A4FCE, 0x517BEBB3, 0x4DDBFCD8, 0xB2E9A517, 0x655E2E28}};
        static const BigInt<256> var_b = {.std_words = {0x9BE19E68, 0xDD4141D0, 0xEC295FA1, 0x79D26E0D, 0xABD68B9D, 0x846F32CF, 0x5A42876C, 0xB12949E9}};
        BigInt<512> var_expected = {.std_words = {0x10B6DA10, 0x10B5965B, 0xEBD0383C, 0x70B20FA1, 0xDD36F4DE, 0xEE608FC2, 0x30004015, 0x401923F5, 0x87CC0E1E, 0xF6F7453C, 0x8172F88F, 0xC5D89344, 0xB96D138E, 0xDC334503, 0xC9D744C1, 0x46267743}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 172 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x98890C6C, 0xBBB48495, 0xC732C861, 0xAFDB303F, 0xB0877BA5, 0x6D1B69C0, 0x9DB5E0F0, 0x95ACCE4F}};
        static const BigInt<256> var_b = {.std_words = {0x61F5DB4B, 0x0AD64C5B, 0x14D561D9, 0xF4AF4466, 0x7C6A48AF, 0x4953323C, 0xA4F36AF4, 0xAAD4ABD3}};
        BigInt<512> var_expected = {.std_words = {0xBD2307A4, 0x7FF53492, 0x983B3543, 0xB2F31BCC, 0xD2A5651D, 0x76000173, 0xA51AD2A6, 0x3EC93203, 0xC3FDB275, 0xE2FD8E4A, 0xBFB5C155, 0x075A95A8, 0xA5F5D9B3, 0xA1534C21, 0xE457A1B0, 0x63E11891}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 173 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xBCC0A316, 0x89087A4C, 0xB232A661, 0xAD9BAB0C, 0xD2342DB2, 0x1095844A, 0x9CDC2F74, 0x1DCD91D3}};
        static const BigInt<256> var_b = {.std_words = {0xCE6FC58B, 0x6ECA8536, 0x44DE7CD8, 0x97F45E32, 0x98868DDA, 0xEC6A676C, 0x37FD169E, 0x319D2022}};
        BigInt<512> var_expected = {.std_words = {0x24A27AF2, 0xBD992451, 0xFBB04563, 0xB89159B7, 0xD9B033CE, 0xE70A80FA, 0xCE6A5E0E, 0xE7171825, 0x58AA77FA, 0x13C1E2B3, 0x4532C7A2, 0xA08065B6, 0xBA22EA35, 0x6C4B02FB, 0x9DD9CAF4, 0x05C6A3B9}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 174 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA69794ED, 0xE22F77F8, 0xB1AF462F, 0x4170409F, 0x588AB3CB, 0xBB3D2D64, 0x281BD585, 0xBB165719}};
        static const BigInt<256> var_b = {.std_words = {0xB3960AC5, 0x802DFCDC, 0xA5A8DF6A, 0x8FCA4EB9, 0xC1257192, 0x90F724DB, 0xAAD1900E, 0xA414A299}};
        BigInt<512> var_expected = {.std_words = {0x1854DC61, 0x1FEAEA79, 0x36BFA84C, 0x4094B68B, 0xBC14AAB7, 0xD44DF039, 0x18EBAF97, 0xAA3C78B5, 0x576B065A, 0x2A26592D, 0x3D5BF8F7, 0x4867D823, 0x5A5766C2, 0xF67B6235, 0x5BF6ECBB, 0x77E9645F}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 175 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x48DD08E6, 0xDAB27131, 0x0FE94857, 0x39BC5865, 0x25BA868B, 0x3176ED0D, 0xFA3DCE64, 0x6B0925EB}};
        static const BigInt<256> var_b = {.std_words = {0x1FC66B21, 0xF494E41A, 0xA1B3EC15, 0x4941A845, 0xF874F13A, 0x9BCDD4E3, 0xD9BB7384, 0xA1DD15F1}};
        BigInt<512> var_expected = {.std_words = {0x831A47A6, 0xE9990F33, 0x4FC5C07C, 0xD5C34EF8, 0x428A845A, 0x9985BE8F, 0x1798C415, 0x2A37B8D8, 0xBAD627BA, 0x39EFBDF5, 0xD80EDC6B, 0x8B2ED910, 0xDB0F197A, 0x1E1B5A9C, 0x03DA15F6, 0x43AD30EC}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 176 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD3FE6FB8, 0xC7485501, 0x5382AED9, 0xA12F60DF, 0x573083D3, 0x7A5AED38, 0x0BB2F92E, 0x6A1E4680}};
        static const BigInt<256> var_b = {.std_words = {0x64802CD3, 0xBF6DC8E8, 0xE12A3998, 0x731D86CC, 0x7EE365F8, 0xB2A4C2AD, 0xDA6E1766, 0x027C33F3}};
        BigInt<512> var_expected = {.std_words = {0x31E9B4A8, 0xA628C28D, 0x068A4E55, 0xC900122F, 0x0221DB54, 0x81E8F23D, 0xC6175496, 0x5B24A021, 0x88439515, 0x060E7520, 0xDAA5ABB0, 0xB6DE6E63, 0x0C0C4017, 0x716D23AB, 0x4370E941, 0x0107B8C0}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 177 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB71723F2, 0x3E28EEB6, 0x48133D34, 0xC797F225, 0x51A36C14, 0xD911D802, 0x93147FF7, 0x36983947}};
        static const BigInt<256> var_b = {.std_words = {0x147E2991, 0x174C6AB3, 0x4D7690A8, 0xF8A8A1BD, 0xD432547D, 0xBA675BE1, 0x07967AE6, 0xE724BF27}};
        BigInt<512> var_expected = {.std_words = {0x01F91E12, 0x8B8EBB39, 0x55608AD2, 0x43A52DD0, 0xB48EB8B1, 0x876E2DA4, 0xDBA5B91C, 0x966A038B, 0x2430D561, 0x10B4861C, 0x21524EC9, 0xDDFF15D5, 0xD77FFEDA, 0x9C18FE80, 0x89538FF6, 0x314B31DB}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 178 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA6012DF8, 0x13570788, 0xF6B76308, 0x37AF1D97, 0xB323557B, 0xD31EB5F5, 0x0CC37B88, 0x8B52784D}};
        static const BigInt<256> var_b = {.std_words = {0xFEBD9284, 0x6F3B5EA5, 0x0ECAFBBC, 0x0783FE48, 0xBB86A937, 0xD784E06B, 0xFA64F1F9, 0xAC8E1881}};
        BigInt<512> var_expected = {.std_words = {0x44EB23E0, 0x4D8F3C75, 0x3C250347, 0x000291A6, 0x65F364F0, 0x5002BB6C, 0x59116BD5, 0x29654165, 0x749F8BE1, 0x9A947569, 0x9C612825, 0xB2333838, 0x1F783D36, 0x0E25D3AE, 0xF76BBCD7, 0x5DE8BDE8}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 179 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9164368C, 0x5CFABC37, 0xA5A0A445, 0xBFEDB697, 0x5F2CE886, 0x2EAFB530, 0x2F6BF328, 0x66920D62}};
        static const BigInt<256> var_b = {.std_words = {0x35954959, 0x7E0E56C7, 0x8EB6CDE2, 0x0B702AA7, 0x3475577E, 0x703D8FD6, 0x8B279813, 0xEDC01DCB}};
        BigInt<512> var_expected = {.std_words = {0xDAE0E2AC, 0x732A1539, 0x8CBA6E7D, 0xAFAD0846, 0x6E1E2D70, 0xEF369A1E, 0xA1ADAE45, 0x210AAEAB, 0xF738BDBE, 0x435A7F88, 0xC6E822ED, 0x04F432A7, 0xA0D4C722, 0x41F7BDE0, 0x08A067C0, 0x5F422FDE}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 180 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 157 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 158 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 159 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 160 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 161 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        BigInt<512> var_expected = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 162 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 163 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        static const BigInt<256> var_b = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 164 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD0557071, 0x17D1A2D0, 0x7279507D, 0xA908FBE4, 0xA0DB502A, 0xC57797D4, 0x524BC56C, 0x699F472C}};
        static const BigInt<256> var_b = {.std_words = {0x864A59B5, 0xAA7A2D86, 0x665DF893, 0x6E8FD9C7, 0xB8AC6E01, 0x8F393EFE, 0xFBDFEBA5, 0x5A93071A}};
        BigInt<512> var_expected = {.std_words = {0xA729C8E5, 0xC7925FC4, 0xB3A1FFBD, 0x8AC77C9C, 0xCCE16CAB, 0xB0DF1497, 0x9B6F45AA, 0x92001AD1, 0x8E0D30F2, 0x17985113, 0x48535B31, 0x950B96F4, 0xC1ACB124, 0x025B9664, 0xF06CE36C, 0x255EA869}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 165 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1440DD05, 0x62A5DCC1, 0x0709FB0C, 0x31E2C9AB, 0x962CF95A, 0xE19D8E67, 0x9EC159B4, 0x75F060FB}};
        static const BigInt<256> var_b = {.std_words = {0xC73A640F, 0x71305F70, 0x2D2DEC3F, 0xFD43BD7E, 0xE5649B93, 0x019C982C, 0xC1C32CC1, 0x69925104}};
        BigInt<512> var_expected = {.std_words = {0x7C44E74B, 0x40C5EAEA, 0xA75C7D61, 0x09E9DFA6, 0xD0131940, 0xDC161944, 0xBCD6DBBB, 0x32D413D7, 0x561A22D5, 0xF2511825, 0xD07D271E, 0xAA360F73, 0x2FC86495, 0xD0161156, 0xC3531D0F, 0x30A30031}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 166 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x91EE2DCB, 0xBD729164, 0xB510EE9B, 0x6F733470, 0xB61C2426, 0xAE4FE0AE, 0xAFB7051F, 0x3AFFC668}};
        static const BigInt<256> var_b = {.std_words = {0x898F124F, 0x62FD8873, 0x01CD4453, 0x39095409, 0xFDA0121E, 0x97934AB7, 0xF8E0583F, 0xC0DD81FF}};
        BigInt<512> var_expected = {.std_words = {0xFF1D67A5, 0x9BCB5509, 0xE549A09F, 0xA24E2E90, 0xE8BE6BEA, 0x7B9216A1, 0x2BF9E411, 0x8A84E9A0, 0x7E61C898, 0x92BEA660, 0x3F34D4AA, 0x5FAC6382, 0x39FAD455, 0x09E02241, 0xAD45D403, 0x2C72E192}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 167 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x69325DF9, 0x2E2E66FC, 0x769A642A, 0xA126B616, 0x131DC4C6, 0xE26B129E, 0xEF79A8A0, 0x26BC8128}};
        static const BigInt<256> var_b = {.std_words = {0x0FBD612C, 0x2492D540, 0xFE2CCD98, 0xFF7353C0, 0x3283C3B4, 0xA64011C3, 0x2B48DB82, 0x6B26B3A1}};
        BigInt<512> var_expected = {.std_words = {0x22187FCC, 0x284CA02F, 0xB0530A74, 0x778BF452, 0x86295CCA, 0xBA94AA03, 0x527CB64E, 0x70646F45, 0x60559784, 0x839A55F0, 0x53D96565, 0x77537C52, 0x1E740F39, 0x2E0C3AEE, 0x7994EFA8, 0x1036A525}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 168 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFC66B0DF, 0xF9176BE6, 0x84204422, 0x426F1D9D, 0xFC04FEB4, 0x71E8E3DF, 0x064121E3, 0xE40CDAD1}};
        static const BigInt<256> var_b = {.std_words = {0xD8C90867, 0x9A124114, 0x7A75404F, 0x6C0A24E9, 0xF51BDE23, 0xC282B6A4, 0x213E183D, 0xB87AF256}};
        BigInt<512> var_expected = {.std_words = {0xC9EF21B9, 0xF1BAE41B, 0xCADEC6DA, 0xF904496E, 0xD1EE3EFA, 0xB98A95F9, 0x02BCA799, 0xCA11A160, 0xC88C7C71, 0xF73AB13E, 0x3C3A9D38, 0x121FD747, 0xBC076E59, 0x7575E572, 0x64E3DE71, 0xA456C347}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 169 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEC816EF1, 0xA40B85E3, 0x551D99F3, 0x119A6046, 0x04228FAC, 0x9022C19F, 0xDEC122D3, 0x639C8152}};
        static const BigInt<256> var_b = {.std_words = {0xA65E016D, 0xEB65DC44, 0x1097C882, 0xDD138099, 0xF679EB76, 0xC148BFA6, 0xE4CB22CC, 0x33169103}};
        BigInt<512> var_expected = {.std_words = {0x37092D9D, 0xE7483F73, 0x1EBE6381, 0x5F63BCF3, 0xDB18D343, 0x9FCC6148, 0x48AE2A81, 0x03AE8412, 0x039D7F76, 0xE696DA2F, 0x6785FF21, 0x64C04F43, 0x795973E8, 0xF5168E8E, 0xC89B807F, 0x13E0F5A3}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 170 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x19237BAE, 0xF4CFCA0F, 0xA59B5709, 0x0B9D46A5, 0xFB47D758, 0xB42EECD8, 0x9FBD0A49, 0xCEAA4EBB}};
        static const BigInt<256> var_b = {.std_words = {0x7AD674F5, 0x7A8684AC, 0x97DA4003, 0xEE686600, 0x27BA09B6, 0xB8E04DD7, 0xBE4EF6B0, 0xAA318A1E}};
        BigInt<512> var_expected = {.std_words = {0x72743586, 0x65B5F559, 0x16480B1C, 0xFBA6B983, 0xFFA90BB4, 0x01BCF27A, 0x63CC9FA8, 0x7E1E5FC7, 0x1B3255B9, 0x5D4048F8, 0xB7860BC6, 0x7A5AD1FD, 0xCF607B89, 0x192C7833, 0x4A059F96, 0x89651662}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 171 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA4A4D528, 0xEC66D6AB, 0x6CC65FAF, 0x6CE7E3E2, 0xF2E08657, 0x92285900, 0xB391BDD6, 0x94DD8BF3}};
        static const BigInt<256> var_b = {.std_words = {0x954E0D71, 0xEDD10DAC, 0x2B713CB0, 0x7D436111, 0xB9174CAA, 0xFB473853, 0x36083447, 0x2AD3FC70}};
        BigInt<512> var_expected = {.std_words = {0x45C51EA8, 0xECA5D249, 0x7C1AF006, 0x22779B50, 0x15DEE1F9, 0x3964C260, 0x21E5D2E1, 0x6AF172D4, 0x6CCE6A97, 0x75AF82B8, 0x80F597EC, 0xC9B1261A, 0xAE233D4B, 0x55F3A9AF, 0xAB6F8A7F, 0x18E79E5B}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 172 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEF2AFC27, 0xD45D0A1D, 0xE278C6C2, 0xB131EBDD, 0x3BFDF082, 0x20833E1E, 0xC3C78503, 0x610FDC1F}};
        static const BigInt<256> var_b = {.std_words = {0x78B6AA70, 0x2A59E3D0, 0x2204D113, 0xA70E21CF, 0x1CFC3EBA, 0x207B52C3, 0x17AE6427, 0xFF9DB9E7}};
        BigInt<512> var_expected = {.std_words = {0xB9FA3710, 0x6AE2F15C, 0x5AC171C0, 0x8D1E0E49, 0x9C279F70, 0x7096B338, 0xCF6A316E, 0x47336AAB, 0x685E341D, 0x59F90892, 0xCBCD31FD, 0x96CDF322, 0xA2543DC5, 0x085BA112, 0xB7DBEF87, 0x60EA9979}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 173 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9AB4322B, 0x2E1DCBC9, 0x81CE6145, 0x974DD2FF, 0x656301B5, 0x925859AC, 0xB7A5F77E, 0x2120B2C9}};
        static const BigInt<256> var_b = {.std_words = {0xE3DF7B63, 0x54301A61, 0x17452585, 0xC9366BB2, 0x020F902F, 0xFCC5EC00, 0x69FABDDC, 0xB7A2E423}};
        BigInt<512> var_expected = {.std_words = {0x3C3F0FA1, 0xDEAA980A, 0x18B58D41, 0xE1D47EA1, 0x74A6C97F, 0x3A954AA9, 0x84D5030B, 0x5B277B73, 0xC98364F4, 0x56DAFF37, 0x116028D3, 0xE1AEA26E, 0xEE95F23B, 0x16F21DDF, 0x0A58CFEB, 0x17C37405}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 174 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x862AAECB, 0xC138ACB6, 0x01B3992D, 0x1CF6CAE4, 0x43A0D673, 0x5DBAE5CD, 0xB8BDD813, 0x03C55C14}};
        static const BigInt<256> var_b = {.std_words = {0xD98E7B4D, 0xD1BEF852, 0xE27DC34B, 0x80F95CEA, 0x5B46DA76, 0xA4138616, 0x743B6CD7, 0x1E2FABB7}};
        BigInt<512> var_expected = {.std_words = {0xE46C1C0F, 0xA6AAE439, 0xED05ADBA, 0x68435F24, 0x1AC3ADB7, 0x2F32305C, 0x4916B7CF, 0xBC1D6E7B, 0xCBBD8FFF, 0xA63F70D0, 0x4A969435, 0x392152A8, 0xA6A2DD7C, 0xDC14E74F, 0xDDC12233, 0x0071D48D}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 175 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD56FA33F, 0x92BF9109, 0x5D727C0B, 0x7C9F8F33, 0xE4160039, 0x36014BB6, 0x307E0B64, 0x7358A68C}};
        static const BigInt<256> var_b = {.std_words = {0x99895157, 0x460FF274, 0x9C20B07C, 0xA9350273, 0x5AF6952A, 0x6C3EB211, 0xC3E35FC4, 0x429E0D3C}};
        BigInt<512> var_expected = {.std_words = {0xDF4E6969, 0x0469DEBA, 0xFC15467B, 0x37140682, 0x2BA03B4E, 0x3D7F7A10, 0xF93FFFA2, 0xE45E30CC, 0xFB1A1AFA, 0xE0A8EEE8, 0x00A41533, 0xDA9A2AC3, 0xE0A3FBFA, 0x7F969E48, 0xD0858DAB, 0x1E04119D}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 176 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xE8713AFF, 0xE58BC5D7, 0xCC48175C, 0x34470442, 0x9B106044, 0x121D7C53, 0xC7C17EB6, 0x1EAA0860}};
        static const BigInt<256> var_b = {.std_words = {0xA6A89758, 0x981F15CB, 0x9E57448A, 0x603B403F, 0x6DE12CFA, 0xEA5F345B, 0x1D1A9FB3, 0x7028BDAC}};
        BigInt<512> var_expected = {.std_words = {0xC210B0A8, 0x58AA0617, 0xC3F69BD2, 0xF2F7C094, 0x3E0BC31E, 0xB96DB2CC, 0x5B9DFD2A, 0xFA4DDC67, 0x01B49357, 0xED5340BF, 0x19DA1D1F, 0xC6440F96, 0x59D982F7, 0x7D8D4879, 0xCC6D6584, 0x0D6F44F3}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 177 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x5E3865CC, 0x3F9300E4, 0xC8F212A4, 0x0244AB63, 0xF8CCB12B, 0x27E50B91, 0x675F2160, 0xF2CE7408}};
        static const BigInt<256> var_b = {.std_words = {0xBFE682BD, 0xEC30F066, 0x8295CCBF, 0x039C14F3, 0x484832BE, 0xF2204D8A, 0x8D491BB6, 0x34B30DB7}};
        BigInt<512> var_expected = {.std_words = {0xDC9CBF9C, 0x559C2A58, 0x7F33963A, 0x3996E429, 0x61C03182, 0x7115AF18, 0x3280B77F, 0x524CB74F, 0x8005C078, 0x8914EE96, 0x5B19F97E, 0x075F23AA, 0x97FC183D, 0x9A0736B0, 0x6A5A069E, 0x31FBC2EF}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 178 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1AF59A9E, 0x66366831, 0x0A3D94AA, 0xE215EEFE, 0xCC91B397, 0xE967F5C8, 0x39BAD990, 0x1AF1AEB9}};
        static const BigInt<256> var_b = {.std_words = {0xE670F068, 0xA717E83E, 0x2025EB21, 0x2FFA27EB, 0xDAF9BE4A, 0x9B093DE8, 0x5BB10ADC, 0x5BA1FBE8}};
        BigInt<512> var_expected = {.std_words = {0xCDDAF030, 0x4D4973DA, 0x82CD1715, 0x7E5F4602, 0x167FD410, 0xFBC962D6, 0xFB331655, 0x0AB180BE, 0xD44F0E2F, 0xD2BC3FFC, 0xC173DD30, 0x3B01BF4D, 0xA49AC3B9, 0x2A2E05AF, 0x24FF38AA, 0x09A4F59E}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 179 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x3D147733, 0x5F917F90, 0x8A94606D, 0x11363AC6, 0x29BBF4DF, 0x0D3B1837, 0xA551818D, 0x04203E1D}};
        static const BigInt<256> var_b = {.std_words = {0x5CB6D673, 0x6E8B03CA, 0x92B9BE6C, 0xC1D9B48E, 0x5563F1D0, 0x38D1FA18, 0x0FF5C5BC, 0xF4A245ED}};
        BigInt<512> var_expected = {.std_words = {0x9E182DE9, 0x27BA4F7B, 0xAF2F6BAE, 0x26A0A6A6, 0x51B70A20, 0xF4E68660, 0xEF3B35EA, 0x6E8143F5, 0x8BF549EB, 0xAE8117DB, 0x6DE48D7E, 0xC333655A, 0x87A9897C, 0x77B28226, 0x132DA5BE, 0x03F158BC}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 180 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x274C3C45, 0x6DCB0C8B, 0x839646A7, 0x0DE7F1B1, 0x5ECB4776, 0x88CB6884, 0x5451E49F, 0x5D20F029}};
        static const BigInt<256> var_b = {.std_words = {0xA2781AEB, 0x26772A65, 0x2FFECC28, 0xD66FC228, 0x29A091E0, 0x5EAE1D9E, 0x74AC29F1, 0x49859A41}};
        BigInt<512> var_expected = {.std_words = {0xBB725557, 0x9DCD68D3, 0x992B9579, 0xE474BC54, 0x55A8822B, 0x4F941FA9, 0x80C57B41, 0x2CD5D778, 0xABB94C2A, 0xA87BC20E, 0x8766A5F9, 0x29515180, 0x35EF3687, 0x1C1AFEA7, 0x2ECB8E2B, 0x1ABEFEB6}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 181 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x79AD3BA8, 0x1867F253, 0x6CA0CA01, 0x92043198, 0xFE7AD852, 0x90ADD4BE, 0x3021C545, 0x133CF123}};
        static const BigInt<256> var_b = {.std_words = {0x79DBC7EC, 0xF448D9C6, 0x9226B10F, 0xCA72B3C5, 0x088AD95A, 0xE4A6FB28, 0x91F37B29, 0xEA02DB13}};
        BigInt<512> var_expected = {.std_words = {0x45CA96E0, 0xE9EBCCDE, 0xBB514091, 0x469262C2, 0x4E8F778B, 0xF428F0D0, 0x36894E5C, 0x6CF589FB, 0xF51C8052, 0x7965D7E2, 0xCA68C605, 0x07F39DC6, 0xBD7311BB, 0xD7855775, 0xA70C0F0D, 0x1195EB5A}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 182 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x14B31FD0, 0x2292FC9F, 0xFF5F174B, 0x9DD3657F, 0xD8C8E5D1, 0x98ECDA52, 0x62F5E367, 0x51127812}};
        static const BigInt<256> var_b = {.std_words = {0xE274AFC5, 0x3D424806, 0x937E8E39, 0x3CEA28D2, 0xE3C860E7, 0xDDDFFBF0, 0xB1FAD5C7, 0xA2936F33}};
        BigInt<512> var_expected = {.std_words = {0x6AD6AB10, 0x9EEDE7B1, 0xA702DAB2, 0x4CF70340, 0x0BA92265, 0x952ACB3D, 0x4360ABD5, 0x24D22B93, 0x2B8A7AE2, 0x303B654C, 0x5F2ABC35, 0xFE4FD7EC, 0x087B00AB, 0x19C014A0, 0xF649866D, 0x337C60CD}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 183 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1A521B7E, 0x9375A28C, 0x34633249, 0x6CD2BD08, 0xFF0920B4, 0x575BD8DB, 0x525E0AA2, 0x86670538}};
        static const BigInt<256> var_b = {.std_words = {0x1D5D67F0, 0xA6C706FB, 0x4BFA46CC, 0x07FF3878, 0xEAE22CBC, 0x9FED1C83, 0x5C961128, 0x7E3CB243}};
        BigInt<512> var_expected = {.std_words = {0xF8CF7820, 0x4CA7876A, 0x5AC75C7F, 0x7C83C515, 0x01120BD8, 0x2D3E7F0F, 0x719CE49C, 0x8C256D5C, 0xCD95BA84, 0x2282BC82, 0xD33E6DDE, 0x0FE290BE, 0xDBBB07C3, 0xCF0F6D45, 0xF0F0ED88, 0x4246924D}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 184 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEC09FD98, 0xAD85BBF9, 0x46A87403, 0x7B88668F, 0xC3F9AA32, 0xC1E307E0, 0xAAD81AE5, 0x5EF5375A}};
        static const BigInt<256> var_b = {.std_words = {0xAD3EB016, 0x14B10AFA, 0x14C67525, 0x49CBF9F7, 0x8F4CE5C9, 0xBE23AFBF, 0x5BCF3AFE, 0xCC5F6C9C}};
        BigInt<512> var_expected = {.std_words = {0x4A044B10, 0x61857AFC, 0x557A5501, 0x24A061CD, 0x63E8DB14, 0xC74BE9B4, 0x951ECD55, 0x80C1AAFB, 0x86041AB4, 0xDE84253E, 0x10D32EC6, 0xB4453901, 0x659A0C14, 0x6236D819, 0x3D9F9FCB, 0x4BCECD65}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 185 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2AF42570, 0xF7D128FB, 0xAC2D479B, 0x8756A2D9, 0xB5C9C357, 0x0BD736CD, 0x525D24FC, 0xC63A34E6}};
        static const BigInt<256> var_b = {.std_words = {0x51663E76, 0xAB993335, 0x86D62DB8, 0x5F2A6078, 0x82782B9D, 0x11E542FB, 0xB6728574, 0x198D6885}};
        BigInt<512> var_expected = {.std_words = {0x483A61A0, 0x66F1257C, 0x28B99231, 0xC6CF4909, 0xB4CB25DD, 0x4AE346D1, 0xF66F2613, 0xE17DDC21, 0x08DBF155, 0xA34140CF, 0x70945531, 0x5B9CB932, 0x997091D7, 0x083B1004, 0xCFE791E6, 0x13C92E28}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 186 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB5D464EA, 0x36557247, 0x2082230D, 0x8E46B178, 0xA6310B0D, 0xAB3D2DCB, 0x73F179BD, 0xEA4BA03E}};
        static const BigInt<256> var_b = {.std_words = {0x0BD3E649, 0xD22F4242, 0x7A787C17, 0xE688720D, 0xB5E71686, 0xABF3CA77, 0xB8A1C6F1, 0x315118BA}};
        BigInt<512> var_expected = {.std_words = {0xE71902BA, 0xA6B15A88, 0x864A4B15, 0x65EE3620, 0xBD57E832, 0x4CBB0621, 0x74D4A965, 0x5FC2A0C9, 0x36BEB104, 0x842E5F85, 0x3F56AB32, 0x892251AA, 0x7BA464C5, 0x0AC465F1, 0xA2E69AC4, 0x2D22B23B}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 187 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xAE29B561, 0x6E4558C8, 0x9A54D872, 0xCCDB8D34, 0xA87F7390, 0x5427CA38, 0x7836CEF0, 0x39A233C0}};
        static const BigInt<256> var_b = {.std_words = {0x1C463018, 0x2D85438E, 0x0AE1AFE6, 0xBAB4CFF0, 0x5939D5D6, 0xE1C0F2AA, 0xE96172B1, 0x22064E62}};
        BigInt<512> var_expected = {.std_words = {0x5A713118, 0x5F122184, 0xFC2E55AC, 0x790332BE, 0x47B51BED, 0xDBE86022, 0xAF90A261, 0x387898DC, 0xBE0A0399, 0x53204FF2, 0x8EAC32D0, 0x2D8DAFAD, 0xEEFCCED2, 0x8D339FEB, 0x76E11E75, 0x07A8F652}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 188 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x773BE22C, 0xE46358B2, 0x550412A0, 0xBEE27D20, 0x0AA8D240, 0xFDFAD3E8, 0x07FA5233, 0x5FECDA49}};
        static const BigInt<256> var_b = {.std_words = {0x06534808, 0xA05E70C2, 0x8DBD61A8, 0xFAAC8929, 0xDF3A6E4A, 0x4ABDA806, 0x122D1D96, 0x39A30AED}};
        BigInt<512> var_expected = {.std_words = {0xEDBF7160, 0x1F31AC2B, 0x6981CF2E, 0xF839BB90, 0x7CC0D071, 0xFCDA3459, 0xA6906A03, 0x86BD2937, 0x4C27CC17, 0x30413617, 0x7A6079B4, 0xAA0AB0FB, 0xEE42766B, 0xBB856757, 0x54E34FAD, 0x1598D481}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 189 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB12C0E18, 0x1E4D27C8, 0xC8302732, 0x22417735, 0x5F5518F3, 0xDAC67C73, 0x0BC6DC62, 0x49DE6F55}};
        static const BigInt<256> var_b = {.std_words = {0x876F5C9E, 0x5284805F, 0x9EC345A5, 0x01725420, 0xF7F7ABE4, 0xB9A8DC38, 0x3B8181DF, 0x028D5F7A}};
        BigInt<512> var_expected = {.std_words = {0xF2A952D0, 0x3E22F5F9, 0x84BF2804, 0xD0A38E52, 0xF7C5E01E, 0xC7734377, 0x5A0F10ED, 0xBA7B883D, 0x9B6B32E8, 0xA085B833, 0x5A8ED037, 0xEDE3EA72, 0xC7C90799, 0xE8B6D494, 0xCC6C4A5E, 0x00BC87EE}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 190 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x3C0A1D4D, 0xE1C81DAF, 0xAD49296C, 0xF4C5588F, 0x77F82741, 0x61909A31, 0xAD700A59, 0x250105EE}};
        static const BigInt<256> var_b = {.std_words = {0xA3035780, 0xA6117214, 0x1541BC63, 0x6DD508DD, 0x93CA26DC, 0x43E27117, 0xAF7009AD, 0x4A6564C1}};
        BigInt<512> var_expected = {.std_words = {0xD3EAD180, 0xE4611DCF, 0x13188E4A, 0xF0E824DA, 0xEC881C59, 0xB4D04A4E, 0x8F74F372, 0x8E8BF1C7, 0xAAA3CB7C, 0x19E241E9, 0x897A25A8, 0x8A9F57D2, 0x827E6F5C, 0x46ABE067, 0xBABF69C9, 0x0AC0F3AE}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 191 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x39DB036D, 0x301A9A79, 0xFD1E3978, 0x71F9F6A9, 0x63D85683, 0x45A493B6, 0x55AC70FF, 0x5E83C510}};
        static const BigInt<256> var_b = {.std_words = {0x9A790024, 0x42C5C495, 0x0CAC2869, 0x1B4A7BEA, 0xE36A755F, 0x3FB865AD, 0xF631DC75, 0x1FDB409F}};
        BigInt<512> var_expected = {.std_words = {0x53517B54, 0xCBD14411, 0xE98CF761, 0x80CCCA8B, 0xF98EF779, 0x78F7A7B2, 0xD59C8C59, 0x0EAEEC02, 0x2F615445, 0x9FC9F71A, 0x7FB43A3B, 0x35C19E9B, 0xF88C39F9, 0xD7B7380F, 0x8F59AEBE, 0x0BC2E772}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 192 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x09B1FBDA, 0x534F55CC, 0xF0701FE7, 0x17EDFC3A, 0x74228E65, 0x7DE6FEDD, 0xAD97C905, 0xA2086945}};
        static const BigInt<256> var_b = {.std_words = {0xED4D8487, 0x0C5129FA, 0xDB320C3E, 0x27B4A61D, 0x59FF8046, 0x40B8291E, 0xD9AF6FDF, 0xCE7A4ABC}};
        BigInt<512> var_expected = {.std_words = {0x754A37F6, 0x6B8C012E, 0x8200B1F6, 0x76B73177, 0xBC555C1F, 0x2C7CEF69, 0x7209C2DF, 0x09263C29, 0xF40768F9, 0x662387BA, 0xF7381336, 0x75C105B2, 0xA2718C0E, 0x8E38001B, 0x33487D3C, 0x82B02C06}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 193 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x4EB7987A, 0xCC91AC43, 0x00802987, 0xA20BA185, 0x3BFA1049, 0x3D22F8C1, 0x9D4D28C3, 0xDF793B7B}};
        static const BigInt<256> var_b = {.std_words = {0x5C1F5A55, 0x27AAA4E1, 0x1B4CE4ED, 0xF0382BBD, 0xA62CFD00, 0x1CFF3154, 0x61199E9B, 0xE37D36F4}};
        BigInt<512> var_expected = {.std_words = {0xFD568482, 0xD36D8A46, 0x582E3C3B, 0x1BEF433E, 0xF53100E0, 0x2ADE7279, 0x92FFAC75, 0xB0A63E77, 0x4652A1B4, 0xD7ABCF4E, 0xB90A9A93, 0x9EBB5E4B, 0x2502773C, 0x1AC8D4DF, 0x8EB34BA7, 0xC695CDE9}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 194 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xE843C561, 0x6376DEFD, 0xE69C49EB, 0x0FE92D45, 0x8989E6E3, 0xFA59282F, 0x4F75300B, 0x40D5B877}};
        static const BigInt<256> var_b = {.std_words = {0xE9BE9214, 0xF95827EC, 0xA546CD7B, 0x110F21C6, 0xBA250453, 0xE788B7AF, 0xD7713F37, 0x2C9B5F6E}};
        BigInt<512> var_expected = {.std_words = {0x92DABD94, 0xCD3207AA, 0x077D8DA2, 0x342970EC, 0x9676E319, 0x3673A654, 0x4F04B377, 0x62494E1B, 0x2375C5E9, 0xE6278626, 0xD59912D6, 0xA0E03824, 0x465F89E9, 0x28CFF3B7, 0x93BEF63C, 0x0B4C1546}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 195 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF9E6A03F, 0x1A4D3C6F, 0x9BB87B3B, 0x9C125F8B, 0x7010E8CE, 0x6917826B, 0x2BD25100, 0x34FEBC63}};
        static const BigInt<256> var_b = {.std_words = {0xD63F8946, 0x28C99844, 0x92D9E804, 0x684E3F4B, 0xC7BBD6B0, 0xF880AE2A, 0xC4204702, 0xB6D61F93}};
        BigInt<512> var_expected = {.std_words = {0xDA52883A, 0xFACAB5CC, 0x8184BEFC, 0x7FFC26E2, 0xEB691DBC, 0x20B1251C, 0x1CD9D668, 0xC1222066, 0x9FFB2D99, 0x7623C6C2, 0xC70A7AE3, 0xFF707D5A, 0xF89E5A7E, 0x6043047D, 0x6BBE0D6D, 0x25D96D69}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 196 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xE17A4379, 0x38714FE5, 0x58F46D27, 0xC4DE912F, 0x40F572F3, 0x80BBB164, 0xDBD3072C, 0x668D4744}};
        static const BigInt<256> var_b = {.std_words = {0xA207F892, 0x97995645, 0x3CB48889, 0x12C0562B, 0x3E6EC04A, 0xE291F0A6, 0xF081657A, 0xCD513E4B}};
        BigInt<512> var_expected = {.std_words = {0x7366B302, 0x28EEA230, 0x5E0D8509, 0xCBF8003A, 0xF5CB68F6, 0x9CF1E323, 0xD2D2EAD9, 0x5B82DD3C, 0x2443F955, 0x279436B7, 0xDA38A7A1, 0x7E6CF1C4, 0x22B3524A, 0xD9B8D69A, 0x53D06195, 0x523FADBA}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 197 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x4234643D, 0x4299F25D, 0x95316D14, 0x473DCAAB, 0x89D4BE09, 0x72CE419B, 0x47261D66, 0xC5A0D36B}};
        static const BigInt<256> var_b = {.std_words = {0x0FDE7163, 0x6CEC277B, 0x3B0E1D96, 0x6CAE209C, 0xCF7A1F1A, 0x7A359B5B, 0x66752DE1, 0xFE1A7136}};
        BigInt<512> var_expected = {.std_words = {0x3A67B097, 0x47F1D3E7, 0xC8EA5628, 0xEAF734CA, 0x21C93D22, 0xBAE9D36A, 0xB52EE05D, 0xA5DEF1F1, 0x05172811, 0x2108D490, 0xF8EC74E7, 0x40F67DAA, 0xE1B66428, 0x2B91223D, 0xE5D4883C, 0xC429FB7F}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 198 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFCB1E40F, 0xFC265F97, 0x0CA295DF, 0x1F878B84, 0x1E91D798, 0xB64F735F, 0x9941F353, 0x7DAB4331}};
        static const BigInt<256> var_b = {.std_words = {0x1EFD3E8F, 0x0CB7A48B, 0x6937E744, 0x13B56146, 0x6CED9080, 0xD704A296, 0x6EEFBDE6, 0x18FEF2C5}};
        BigInt<512> var_expected = {.std_words = {0x616D0661, 0x52D139C6, 0x8ADB048E, 0xC91F3360, 0x86B035F0, 0x10432DE1, 0x72931927, 0xD4BB8299, 0x29F79545, 0x7E4F1582, 0xB98690A0, 0x9323DC5A, 0x3BA8DFD4, 0x5B1B3B29, 0x22591D46, 0x0C453566}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 199 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x300D408E, 0x6B772E7E, 0xB65747CD, 0x8B4E8598, 0x0F643B29, 0x0006CA34, 0x39FACD88, 0xFB456179}};
        static const BigInt<256> var_b = {.std_words = {0x10219EF8, 0x1C1211C4, 0xDD277051, 0xE39060F0, 0x45B0404A, 0x4C089547, 0x9188EF91, 0x25542D68}};
        BigInt<512> var_expected = {.std_words = {0xECFC2D90, 0x48D6CC5C, 0x4A98FF52, 0x81A849EA, 0x75CB4F15, 0x8EE688A5, 0x33B6310F, 0xFBC7723F, 0x03274EF8, 0xF85BE55F, 0x773FAB55, 0xF113D3FF, 0xA830A1C8, 0x91D0A8C7, 0x5652E2A6, 0x24A3A66C}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 200 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x40E9DD6D, 0xD5324F5E, 0xCCD4DE7E, 0x072F14F5, 0xAEEC1C9B, 0x46CF4C71, 0xD1102390, 0xEBFDF0DF}};
        static const BigInt<256> var_b = {.std_words = {0x6698693C, 0x8189AC55, 0xF20FC336, 0xFAEFB0F3, 0xCC9B5D24, 0x6F079B08, 0x980D06CF, 0x75D37532}};
        BigInt<512> var_expected = {.std_words = {0x09599A8C, 0x62ECBCFD, 0x5CF6CC4C, 0xFF993BBF, 0x16D5C1F9, 0x22F52271, 0xFD1F6820, 0x644D62E1, 0x78B94B4A, 0x23EA4A41, 0xCC4D8766, 0x5FA1491A, 0xED7C2011, 0xC1835273, 0x85DFD002, 0x6C9DFD6D}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 201 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCC8349F5, 0xBE9CEE7B, 0xC69BB107, 0x519D960C, 0x8A4049D1, 0xBBF0796D, 0x4AC2ED6A, 0x3D265A8D}};
        static const BigInt<256> var_b = {.std_words = {0xE05320D5, 0x606C7584, 0x40E86B91, 0xB54152FB, 0xB286B1D8, 0x14D99F9A, 0x8C0FE64D, 0x935FE0B5}};
        BigInt<512> var_expected = {.std_words = {0xECEA28D9, 0x6353312C, 0xE91ABB04, 0xCA3D1FDD, 0xEBFBD34D, 0xE3BA82EE, 0x1A26A85C, 0x71E02681, 0x077CF9DC, 0xEA042CCF, 0x2ECC8912, 0xBD1E0234, 0xB8D76AD7, 0x421F3882, 0xA92B19C2, 0x2333ECE7}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 202 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB5C44C71, 0xECE355F9, 0x5EBF4E7A, 0x65B7956B, 0x76FBB121, 0xD666EFD9, 0xCB570649, 0x1BA7E205}};
        static const BigInt<256> var_b = {.std_words = {0x81F65252, 0x1E1D604D, 0xA1013A3E, 0xB18622C7, 0xE8555DDF, 0x51B3B609, 0xB673CE98, 0x4CD924EC}};
        BigInt<512> var_expected = {.std_words = {0x7EF2AE32, 0x546A7958, 0x596AE9DD, 0x5EF5DE18, 0x0C994D5D, 0x434D1264, 0x8F8597BE, 0x275D1DC1, 0x2EA54550, 0x7F4BD7BB, 0xC4F9A3AA, 0xDA92A33A, 0x5FB00F96, 0x24E616E0, 0x7D8A3DFE, 0x084D4C65}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 203 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1D4EEF66, 0x6372BB2E, 0x8D720387, 0x8014C249, 0x814F9B3C, 0x4B35C70F, 0xC0B67D87, 0xF3CD7E7F}};
        static const BigInt<256> var_b = {.std_words = {0x88E57485, 0x60610249, 0x2C95C6EE, 0xCB20A5F1, 0x9E0CB917, 0x7B7BB0EE, 0x9F03968C, 0xAEEE9869}};
        BigInt<512> var_expected = {.std_words = {0x54BA97FE, 0x86455B1D, 0xDE53FD5C, 0x7D908EDE, 0x885CFFC2, 0xAC74D0FA, 0xE017C6F6, 0xD05572E9, 0x199C68E8, 0xDC319C9B, 0x0BAD2541, 0x3B05C496, 0xE2B60937, 0x14927557, 0x0995FC27, 0xA698E62D}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 204 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x648C5983, 0x693D08D9, 0x8C98A304, 0x2095C493, 0xFE146E7B, 0x0FB7A770, 0xD0F0FC3C, 0x721D358B}};
        static const BigInt<256> var_b = {.std_words = {0x775811C5, 0x0BB2B2CF, 0x3C54BF2C, 0x20A31DF5, 0x46DC57B9, 0x2716E682, 0x10FD6C9B, 0x06EB3D41}};
        BigInt<512> var_expected = {.std_words = {0x5BFA94CF, 0xE3D583BF, 0x8397AA1E, 0x82992378, 0xB5BEE303, 0x66685E8B, 0x8D142E2B, 0xEF414421, 0x31201B9D, 0x8F288D10, 0x1142E2E4, 0x5B60A57D, 0x873DE83E, 0x90BAB4A7, 0x64FE270A, 0x03158B5F}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 205 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2CC69B8A, 0x821591C4, 0xD354967C, 0x0133E34A, 0x7DDA2DC8, 0x57EE872B, 0xE4D328DD, 0x851D161F}};
        static const BigInt<256> var_b = {.std_words = {0x106964A7, 0x438B1BA4, 0x6AF8F404, 0x0CA2FEEC, 0x903430CE, 0x29B7367B, 0x12A22283, 0xE086E247}};
        BigInt<512> var_expected = {.std_words = {0x35EB5F06, 0x88D6B20D, 0x52A0D517, 0xD0D77592, 0x5A77C971, 0x5DD7065E, 0x3D6453A7, 0xFEBEA93E, 0x839E7095, 0x868605CA, 0xF82ACE9D, 0xEDC0C353, 0xA42CA3A1, 0x40399C04, 0x1F342F0C, 0x74BF963E}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 206 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x552C59C6, 0x74F6C3D8, 0x1C9B2613, 0x20D17957, 0xCFF4928E, 0x99D427FB, 0x267A09BC, 0x5A2BC84D}};
        static const BigInt<256> var_b = {.std_words = {0x522358D5, 0x6FBC42A9, 0x8DD32DD3, 0x2D83ACD0, 0x6ED3E7C6, 0x97313ADF, 0xEEC8EE5F, 0x0AB858A3}};
        BigInt<512> var_expected = {.std_words = {0xCED4C1BE, 0xA75379CD, 0x13070A53, 0x2F049A02, 0x330B4AD6, 0x9A3182AA, 0x948622E3, 0x506E0E3F, 0x0C45C4CF, 0x8B3018FA, 0xD32B8EB4, 0xDD9B4927, 0x98A82C10, 0x66619F12, 0xC5CAF4D4, 0x03C6A483}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 207 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00EA56B5, 0x4357C9A9, 0x60BF1765, 0xBA0B472B, 0x058FC867, 0x88AA3CB3, 0xFED9757A, 0x5C49A738}};
        static const BigInt<256> var_b = {.std_words = {0x7F95E5D6, 0x33B80469, 0xC05FBCE7, 0x604D9424, 0x11D543FA, 0xC647A751, 0x2D6CBF44, 0x9081BFD2}};
        BigInt<512> var_expected = {.std_words = {0xA5CD644E, 0x7428EEBD, 0x1D1FBE63, 0x97827B1B, 0x8C423C04, 0x0A95889A, 0x3D3456E1, 0xB1562F7D, 0x7A46CDFD, 0x04A92A6F, 0x96730BC2, 0xDD4727A4, 0x2E23FB88, 0xBC4DE529, 0x0BA196F9, 0x34183454}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 208 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x8F34EFFC, 0x357A19F5, 0xD8057E33, 0x4D088DD0, 0x70BACE71, 0x1B4851B1, 0x165683A4, 0x3AEF7809}};
        static const BigInt<256> var_b = {.std_words = {0x17E0D9F9, 0x73E40370, 0x5BCFD9FF, 0xC278965E, 0xE9C3BC20, 0x4AFBED7E, 0x983A0AC2, 0xC0C3E09C}};
        BigInt<512> var_expected = {.std_words = {0xCA6A081C, 0x80E8685D, 0x339B2263, 0x1D762A76, 0x308AD7C3, 0x2E8A8012, 0x46DE4D5F, 0x52D3F8EF, 0x4D14C272, 0xB47400BF, 0xC62136DF, 0x71075EBA, 0x0383B935, 0x571DCCEB, 0xD5AD8BB7, 0x2C60B224}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 209 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA25B68DD, 0xCDBC05AE, 0xFD32DBF6, 0x95450643, 0xA27E8083, 0x866C5A86, 0x574DF90A, 0xE0D9B300}};
        static const BigInt<256> var_b = {.std_words = {0xDD45FFB3, 0x56EA0BC4, 0xF79CC4C9, 0xB0BEC57A, 0xA8A8361D, 0xF9DC05A7, 0x39272204, 0x270CA391}};
        BigInt<512> var_expected = {.std_words = {0x9FEF7587, 0xC1DB6132, 0x18E3EA10, 0x72D5D38A, 0x1E115F82, 0x5663DF3F, 0x0910D4F8, 0x4EC7C785, 0xA85A4322, 0xA5DE2869, 0x371DE1D4, 0x567DEB23, 0x8EC308F1, 0x00D41182, 0x9BCB6B47, 0x224C4423}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 210 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1BD92FAA, 0xD3E7357F, 0x871B7FB2, 0x906BAE2F, 0x6BE93DAE, 0x3F0EFF6D, 0xE9AAC8A0, 0x7ADB5BE5}};
        static const BigInt<256> var_b = {.std_words = {0xD13BAA21, 0x3F06E9F9, 0x6E1BA3ED, 0xC7E9797D, 0x3E1ADDA3, 0xE85C7077, 0x57F91072, 0x91658F0B}};
        BigInt<512> var_expected = {.std_words = {0x96D408EA, 0xAAF91F32, 0x535000E9, 0xF1E7C7A0, 0x2AB1F1BD, 0x18647265, 0x8AC7FE64, 0x7486C190, 0x82D8ADD0, 0x8EF8DCCF, 0x6B66BA6D, 0x6CAD35FF, 0xBEDDA3D4, 0xBB524612, 0x75095FE7, 0x45C6FC3E}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 211 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1A61F906, 0x4A7F19E6, 0x70342CA1, 0x7A1B5F78, 0xDB1E3ABE, 0xF9AA9468, 0x357687E5, 0x77AB7163}};
        static const BigInt<256> var_b = {.std_words = {0x3379AA81, 0xD557B3AF, 0xD7052A54, 0xE3A5B6DF, 0xDE4D2390, 0x6C1A6FAA, 0x7CDCF4F5, 0x0C286BDE}};
        BigInt<512> var_expected = {.std_words = {0x40927806, 0x2F65447D, 0x1944E72F, 0xE2FF1AF4, 0x7F4D8196, 0x1DFBDEE1, 0xD25EA6A3, 0xED501E3E, 0xDFD6F845, 0xE9BCD3F2, 0x60F143B6, 0xA314D1A6, 0xCFB4187A, 0x8C10186E, 0x07710908, 0x05AEEE87}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 212 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00F2C1EA, 0x77124D4D, 0xF1220094, 0xD0BF4018, 0x45696DAA, 0xAB97CF0C, 0xE562F025, 0x83B6F625}};
        static const BigInt<256> var_b = {.std_words = {0x8607A0CF, 0xFB318E70, 0x8D0F07A4, 0x2250E622, 0xF626E8FA, 0x19346E20, 0x71F0E157, 0xE4C8E51F}};
        BigInt<512> var_expected = {.std_words = {0x46E30C36, 0xC1455C5F, 0xFD537324, 0xCA6C86DD, 0xFBD68755, 0xF6678CCF, 0x13ABCCCE, 0xA15480FC, 0xCA2259A3, 0x9FD2289F, 0xAC84E258, 0xE45BE873, 0x3721EA5A, 0x8E52902B, 0xE5DEBA13, 0x75B6500C}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 213 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x6FE4B6A9, 0xE08BF3CA, 0x824CA01C, 0x505C0F46, 0x39492B25, 0x89502766, 0xE260661B, 0x8BEE84B9}};
        static const BigInt<256> var_b = {.std_words = {0x8952B4DD, 0xD86ADB46, 0x29740F2F, 0xE1C6E808, 0x3A47BE61, 0xC597A268, 0x3FD94754, 0xA7AA5AB7}};
        BigInt<512> var_expected = {.std_words = {0x5C0283E5, 0x27BB8EA8, 0xC178EF08, 0x76E4DE3E, 0x3EA81E11, 0x55EBC916, 0x8377DE59, 0xBF76CF6B, 0xA3423DF1, 0x70B24486, 0xBB70B769, 0x58790A0C, 0xC513A632, 0x39064B1A, 0x6B2DE7EC, 0x5BA5B68F}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 214 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x47FB0087, 0x49810368, 0xDE66AADB, 0xF55D33F1, 0x88855CBE, 0x08C9EE74, 0x542C7CB3, 0xBC9A7A84}};
        static const BigInt<256> var_b = {.std_words = {0x3E38B78E, 0xCFABE281, 0x828732C8, 0xBD39762D, 0x991E5870, 0x8452DCED, 0x2F4FDB56, 0x21EDA6A1}};
        BigInt<512> var_expected = {.std_words = {0x2A22CBE2, 0x5E5D6A5C, 0xDC1F72E0, 0x52821931, 0xB3A7B286, 0x50519001, 0x732D3748, 0x1983D1D0, 0x7BBCEB8B, 0xAA447087, 0x398D5C24, 0x836DE4B7, 0x357BABDD, 0x4D32E37B, 0x66CFB6D2, 0x18FEFF91}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 215 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA973738F, 0xB8838815, 0xFC07698C, 0xFF6AAEF6, 0x443B5D48, 0xDEBB2025, 0xA5DD7F08, 0x8327BA61}};
        static const BigInt<256> var_b = {.std_words = {0xE618A011, 0x86C1EC73, 0xB345303B, 0x93F9D5FD, 0x45FB173D, 0xADE08C3C, 0xCBAE0303, 0x603D1316}};
        BigInt<512> var_expected = {.std_words = {0xB84C0C7F, 0x3442ED3A, 0x9AD028B0, 0x45D16028, 0xBE0A348F, 0x3DB8D1A7, 0x2A85F024, 0x485B1D8D, 0xC88A3D19, 0x549736CF, 0x90F0274E, 0x6856DB0A, 0x4249A921, 0xC0BA69DE, 0xA8108075, 0x314E3023}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 216 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF7141FBE, 0x716FD8B4, 0x1636CCA6, 0xE832DCAA, 0xBCED7E70, 0xFEFADFD0, 0x7D790AD4, 0x8DF6FDAA}};
        static const BigInt<256> var_b = {.std_words = {0x02E7723F, 0xE2EBD22D, 0x14E3135F, 0x7F48E94B, 0xAE19C409, 0xD37D0117, 0xDA88CCF2, 0xB1A551F9}};
        BigInt<512> var_expected = {.std_words = {0xE4886BC2, 0x7E3D765D, 0x62AAB696, 0x7974A392, 0x5B29462C, 0x66B62911, 0xB665D297, 0x417D1C4F, 0x780F3C9E, 0xE54CF280, 0x6CFAA91D, 0xAF191361, 0xA4BA6ECA, 0x03100241, 0x14536CEA, 0x6283730A}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 217 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD240C9AB, 0xFABBBCD7, 0xA4F7A5B0, 0x6F3E0795, 0x83962EBC, 0x9FBFABA3, 0xC58093E4, 0xC82EC0BF}};
        static const BigInt<256> var_b = {.std_words = {0x5337897C, 0x092E027D, 0x3F5C72FC, 0xE0298AF9, 0x86B45ED9, 0xCB74D14C, 0x66325B55, 0xA05D8F4B}};
        BigInt<512> var_expected = {.std_words = {0x480B31D4, 0xE177F3DB, 0x344A528C, 0x73E344C1, 0xEC5A0D20, 0xD356EF80, 0x84376D92, 0x8E96C232, 0x8A4C3FAF, 0x68C62A88, 0x3510610C, 0x65331499, 0x1852FC57, 0x107641BB, 0xF462B500, 0x7D666180}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 218 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1903474A, 0x17CC8F1D, 0x61E32A97, 0x90BFD179, 0x69B5BE5B, 0x35FA4773, 0xA780085F, 0x5F8CB655}};
        static const BigInt<256> var_b = {.std_words = {0xDA503FBE, 0x5E9EF2B0, 0x0B066D00, 0x51323E79, 0xBE14226C, 0xAC6F808A, 0xB854E855, 0xFB999A7E}};
        BigInt<512> var_expected = {.std_words = {0xAA1A1EEC, 0xF8BFF35B, 0x85B778A3, 0xEC980560, 0xFBA32D08, 0xCB97528E, 0x2B230E94, 0x0996597A, 0x1221C2E5, 0x69CDE2E6, 0xA2B9D072, 0xE1F559AB, 0x8F9158E4, 0xB4B25ABA, 0xE629BC96, 0x5DE84B88}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 219 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEF21BC6C, 0xCD3D4E52, 0x44B0B6A9, 0x88617211, 0x7F60D583, 0x75A259E3, 0x8CA268D5, 0xC030E21F}};
        static const BigInt<256> var_b = {.std_words = {0xD83C0596, 0x87B612ED, 0x931D78B5, 0xB0573D21, 0x86A1A072, 0xC9C75496, 0x5A7D3D74, 0xCE5C1CE1}};
        BigInt<512> var_expected = {.std_words = {0x0FC28348, 0x73EB0E23, 0xC3D12941, 0x0870662F, 0xC30E9E8B, 0x8EC66FBA, 0x9575E392, 0xEB7CD923, 0xC9EA9615, 0x06D6C4B3, 0x94B4B38E, 0x241D007D, 0xC3CB13DF, 0xA3F12D29, 0x2E22A156, 0x9AEC7D35}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 220 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB52DBE1D, 0x623A9CB4, 0x87C5D40E, 0xD518C506, 0x16547E3E, 0x5407B7E8, 0x1C3C647B, 0x99723399}};
        static const BigInt<256> var_b = {.std_words = {0xCDD6D362, 0x69A3260C, 0x3058E5FA, 0x1AC1CC8D, 0x50F00809, 0xB8D561AF, 0x13AEB637, 0x6745E68B}};
        BigInt<512> var_expected = {.std_words = {0x3472AE1A, 0xD7923B58, 0xA746F8BC, 0x3150BD52, 0x5F98BABC, 0xB3DBA42A, 0x48C1097B, 0xFD36901B, 0x3E145C19, 0x76A118ED, 0xEDD498CB, 0xC92DF208, 0x4B40169D, 0x5149B5AA, 0x79CAAEE1, 0x3DE6D8BA}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 221 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0B915B04, 0x5AC6BE07, 0xA3CA8CCC, 0x33F32F1C, 0xBF02E1E4, 0x081F6C01, 0x415F0002, 0xD5ADC1FF}};
        static const BigInt<256> var_b = {.std_words = {0x7CDC050A, 0x29951B5A, 0x797332B4, 0xEC96ED8F, 0xCDD48DCB, 0x4D41C603, 0xEDECC7E5, 0x5360547E}};
        BigInt<512> var_expected = {.std_words = {0x71E4A228, 0x282953E8, 0x3DE41B48, 0x25316ADF, 0x023985EC, 0x0632723C, 0xDB01A016, 0xCFD0904A, 0x2CBE329C, 0x175CC0C0, 0xACD1FFA3, 0x5C63FE76, 0x3039E337, 0x9FB53CF3, 0x77AF0D57, 0x4597BD95}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 222 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD2A00659, 0x7B118956, 0x5037F3BC, 0xA0E75B93, 0x4BA59AB2, 0x05D772B6, 0x236A3EE3, 0xA31397CD}};
        static const BigInt<256> var_b = {.std_words = {0xE4FD94D8, 0x2C0F4FA9, 0x49C51BE9, 0xC2D25F65, 0xED70F214, 0x9F511E73, 0x31D40625, 0x5EF7C2D6}};
        BigInt<512> var_expected = {.std_words = {0xC4A5CF18, 0x21676894, 0x3F0D549D, 0x8F593D63, 0x7C5799C1, 0xD7A72C35, 0xEC927A31, 0x92385C6B, 0x408FF829, 0xD744E873, 0x7236281B, 0xB2981625, 0x7E64D4EA, 0x8E319C94, 0x1516591E, 0x3C7F05C2}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 223 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2CAC642B, 0xCAC63D8C, 0x88E3FD07, 0x58A6C134, 0xCB4ABC23, 0x00641F3C, 0x2C97C726, 0x6F7A103C}};
        static const BigInt<256> var_b = {.std_words = {0x47EDBA6D, 0x17384A88, 0xB8CB724F, 0x7A0FF936, 0xE2443A38, 0x013D2A12, 0x6922B8B5, 0x95611854}};
        BigInt<512> var_expected = {.std_words = {0xEEFCE44F, 0x913ADD5C, 0x520DA39A, 0xE351EFA3, 0x8804F1E8, 0x33650EDE, 0x96E0B87B, 0x926F001F, 0x5535A9C0, 0x6FC9DA9A, 0x588545AD, 0x3721FF41, 0xBE1569AF, 0xD3E45887, 0x601C63A5, 0x410C534B}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 224 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x790C01FA, 0x8A5C6448, 0x84979CFB, 0xD8680A94, 0x91E86C0E, 0xEE914046, 0x048D9CE8, 0xE62DD19E}};
        static const BigInt<256> var_b = {.std_words = {0x266FF6CF, 0xCF29F19C, 0x1FBDB837, 0x32594F1A, 0x1D3F7DC6, 0x0879A824, 0x5C4AE1A8, 0x47D3628D}};
        BigInt<512> var_expected = {.std_words = {0x6201D526, 0x6EAE8DC3, 0xA1CFE6A5, 0x1E8B6708, 0xAC8071A9, 0x8B4A95AC, 0x765883E8, 0xCCD9F25A, 0x35951535, 0x28D299C4, 0x05D22FA4, 0xC32F4050, 0xA048070A, 0x6273FA94, 0x3CF7C47C, 0x4094C583}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 225 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x5A35E4DC, 0x43649292, 0xBD9B155B, 0xDDC1446E, 0x2D6A2FA9, 0x0414F464, 0x95EEC82A, 0xF4BE4AA3}};
        static const BigInt<256> var_b = {.std_words = {0x426A740D, 0x7941266A, 0x17187D15, 0x45FDB713, 0x4ECCDF31, 0x8B0A6482, 0x1403DEBE, 0xFF2D8A8C}};
        BigInt<512> var_expected = {.std_words = {0x7B884F2C, 0xDC866CB8, 0x6EB5427E, 0x07A237DC, 0x785A8BA4, 0x6532858D, 0x976277D2, 0x0D12F311, 0x635FF1AB, 0xA1C11D6A, 0xC07B0B12, 0xC86AAC1B, 0xE5953DE0, 0x9673A136, 0x9089C5A6, 0xF3F51640}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 226 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB1C40EC4, 0xB7DA2853, 0xEC48A67E, 0x656DED3E, 0x70C1CCEE, 0xB8D42E7F, 0x07EB1ABB, 0xC8D3D8C1}};
        static const BigInt<256> var_b = {.std_words = {0x9CF7DC08, 0x796FE104, 0x7A33801C, 0x505A9AD5, 0x67E7AE5E, 0x9DD5769C, 0xDBD779D6, 0x8AD015B9}};
        BigInt<512> var_expected = {.std_words = {0xB9ECE620, 0x4593AB9B, 0x27AFFAFE, 0xE9A7D702, 0xDBE164A5, 0x0C058670, 0xAF437519, 0xF519F270, 0xFD6869DB, 0xB4B78819, 0xF94659CD, 0x0EB87330, 0x4F65C6FC, 0x967FDAF3, 0x5970E880, 0x6CE57003}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 227 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9E92D88A, 0xED7705B6, 0x099867DC, 0xAC20CC68, 0x6BF6E110, 0xBE45F93F, 0xC4CDDE35, 0xCFF7706D}};
        static const BigInt<256> var_b = {.std_words = {0x75728453, 0x7687BB7D, 0x60CE99AB, 0x32B0163A, 0x9829A0F3, 0x93EDBF97, 0x38B88D95, 0xF6660640}};
        BigInt<512> var_expected = {.std_words = {0xA0B75CBE, 0xDCFB47B6, 0xAE1D591D, 0x1D149323, 0x5C4EEFE5, 0x05DDD395, 0x0CE91C1A, 0x2E25E222, 0x0112AB8F, 0xA9522786, 0x730B8345, 0x6F3C508C, 0xBEE368D2, 0xD2FD786C, 0x3F6CF911, 0xC82AA7B4}};
        var_res.multiply(var_a, var_b);
        assert_equal(var_expected, var_res, "multiply 228 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 181 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 182 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        BigInt<512> var_expected = {.std_words = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 183 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA8C695A4, 0x6EA60236, 0xE0A18201, 0x6B58C595, 0x75B299C5, 0xEEEBF59E, 0xF59A0400, 0x05D60350}};
        BigInt<512> var_expected = {.std_words = {0x11285110, 0xBE12EFA3, 0x11C22BB9, 0x29B305F4, 0xED563879, 0x45BF0095, 0xC5BA73DE, 0x38D1DA20, 0x96FCFD37, 0xB21B67F9, 0x52AEF591, 0x9A11AB1B, 0x4B4019E3, 0xC2DF5898, 0xB4FDA102, 0x00220F0A}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 184 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x09BFE261, 0x38AF210C, 0x76B8B1F0, 0xB3291131, 0x7F1655A0, 0x29F63BF6, 0xD4D18964, 0x88E461D8}};
        BigInt<512> var_expected = {.std_words = {0x66ED68C1, 0x535748D6, 0xED3FFA56, 0x7B8025F9, 0xDD081734, 0x39C1049E, 0xFA3D4ED4, 0xC1602455, 0x4733B0C3, 0x3E3CC427, 0x0D4A9A99, 0x2D95034E, 0xA3D8CA81, 0xC3A1D633, 0xD1BFC025, 0x493373B4}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 185 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x5D9C83A8, 0xDEAE5DED, 0x6FC4F265, 0x8A51FFB8, 0x5635B9BD, 0x594932A1, 0x965061EE, 0xE4A4A5CD}};
        BigInt<512> var_expected = {.std_words = {0xC8755E40, 0x860EEC68, 0x8F2689C4, 0x9B18C748, 0x0E7808BF, 0x67DB93BF, 0xCDDBB562, 0x1B4A0D93, 0x61D4CB9D, 0x75010AC8, 0xB58ACCE2, 0x3E2E4F1E, 0x45D549DD, 0xBBA92ACC, 0x0E8A6E4B, 0xCC35B13B}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 186 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0B6D4C00, 0xD36E639D, 0xAEC8BF9B, 0xEB2E6454, 0x1F1504F6, 0xE78661F8, 0x2C90DA95, 0x9A13B8AA}};
        BigInt<512> var_expected = {.std_words = {0xCE900000, 0xDD59CB31, 0x5050DC62, 0xC2F46D1E, 0xBC6B3509, 0xA6199666, 0xFE47DF51, 0x9497A4FC, 0x006DC879, 0x5CFA1846, 0xBF95BBB4, 0x0326E012, 0xE6670043, 0x3F29F4D3, 0xAC15F5AC, 0x5CBBBBB1}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 187 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x61587261, 0x8076D333, 0x5BD5515F, 0xA6685CEE, 0xA4CE6840, 0xF3D670CF, 0x8C8A0BF7, 0xC05F92FD}};
        BigInt<512> var_expected = {.std_words = {0x57CA88C1, 0x2C399DE2, 0x466432B0, 0x127D90F2, 0xCE1D4101, 0xDFFAF47F, 0x8A50F136, 0x9570A496, 0x16AA25BF, 0x07F21A2E, 0x55A5B71B, 0x225BA1A6, 0xDA6E6DAB, 0x5B72641F, 0xBF638FD5, 0x908F802A}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 188 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0D5718C4, 0xC255F8FD, 0x60EC9338, 0xE09396B1, 0xD3BDF955, 0xCF8AA412, 0x2E575636, 0x80291214}};
        BigInt<512> var_expected = {.std_words = {0xBF9D5610, 0xA0FCA98D, 0x585A0F1B, 0x2635D077, 0x8F1D5619, 0x080380B6, 0xE9C91E41, 0x5B6FABE8, 0x3BA3B0CA, 0xF62B7501, 0x8A9E50A5, 0x30B41E52, 0xB761D747, 0xFB41CD02, 0xFA15064B, 0x402918AA}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 189 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA47B8A32, 0x6ABF0B14, 0xECF5DDF2, 0x8F2ABB3B, 0x3F4278A8, 0x818F9EB7, 0x90D75590, 0x9710A79E}};
        BigInt<512> var_expected = {.std_words = {0x26A5F1C4, 0x5978687E, 0x9B5E211E, 0x9CDAB511, 0x19808252, 0x7183F69A, 0x4204EF23, 0x1E237B37, 0x865F4970, 0x93235FB0, 0x8E078FEC, 0xDEF07F27, 0xB8F7CAC6, 0x384ABBFC, 0x7070650B, 0x5924A6D2}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 190 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1ECB69EF, 0xBC7314D7, 0xF4C46931, 0xFFD16CF0, 0x9E0F2C8E, 0x45B0CA59, 0xB2730355, 0xD792B38C}};
        BigInt<512> var_expected = {.std_words = {0x30DFED21, 0xBAA795E7, 0x24EF5B6A, 0x8B00DD7E, 0x9AA98DD8, 0xF0FBC2EA, 0xE180FE6F, 0xB893FF2B, 0xCCD72F8A, 0x3CABEC6D, 0x091848DD, 0x0924A1FF, 0x5D9DFD79, 0x892B7A91, 0x9E26C9A9, 0xB587BDA7}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 191 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x58A54A67, 0xF0FAA663, 0xAD2BB466, 0x4FF19A88, 0x490E24C6, 0x09A920BE, 0x9BE62776, 0xA53ABB47}};
        BigInt<512> var_expected = {.std_words = {0xCE65B571, 0x7C332D89, 0xF5562DEE, 0x44CF60BC, 0xEB8BF006, 0xBB0F8537, 0xD1B78450, 0xE76083B2, 0xEFE70CD6, 0x66ACB8EE, 0x06E4508F, 0x2F1FAD23, 0x6FECD503, 0x20313D22, 0xB46B04F2, 0x6AA4C2E3}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 192 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x91BD8753, 0xB52F1385, 0x13203C7A, 0xF5972018, 0xBFCB82C2, 0xF0082685, 0xD21A6901, 0x7B1DB83B}};
        BigInt<512> var_expected = {.std_words = {0x1E16A4E9, 0xF2772DDB, 0xF3728161, 0x2E8F82EA, 0xAA6B2E4B, 0x56EC1B73, 0xDFF3BAE6, 0xEE1EF621, 0xE87D08CB, 0xAA1F1818, 0xEAC7090F, 0x9E7F88B6, 0x4901C0E3, 0x22A6BDCE, 0xBE0906E4, 0x3B35927C}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 193 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xEDA24BAA, 0xA999C8DB, 0x66F051A4, 0x36B4E948, 0x227BB878, 0xD0E45985, 0xE51687D6, 0x67AA314C}};
        BigInt<512> var_expected = {.std_words = {0x9D850CE4, 0xEBB0FBD8, 0x96CD39F2, 0x2451D5F6, 0xEBDD6F72, 0x15B8297A, 0x837A8590, 0x19F0A699, 0x08885E62, 0xC0B650A0, 0xAA22E5C0, 0xE2F8FFB6, 0x6B242CFB, 0xB7C763D5, 0x63F6EA06, 0x29FA64D1}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 194 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF5D812B6, 0xE297FBB8, 0xA887E88B, 0xAF991878, 0xB885CCD1, 0xB35974A3, 0xE5F999AA, 0x8BC8EE6E}};
        BigInt<512> var_expected = {.std_words = {0xF07E1964, 0x721713CF, 0xB449EF4B, 0xC139D832, 0x3ACCDC57, 0x2E8E27D0, 0x7C0A589F, 0x423F1B06, 0x677CE895, 0xE10069AC, 0xAC38A54F, 0x84A1AF94, 0x2F1EB02C, 0x044D54E4, 0xD916C686, 0x4C53D0A1}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 195 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x158028F5, 0x685BD5A8, 0x20C29A7E, 0xCFD7E5B6, 0x6BAB1837, 0x5ADF2381, 0xE80763F1, 0x9B455D26}};
        BigInt<512> var_expected = {.std_words = {0x2D8D7A79, 0xAC59BA71, 0xD80BA1B3, 0x172678B4, 0x4AE2DED0, 0x03A04D64, 0x6B04D0B7, 0xF372B651, 0xF46D02F4, 0x5BBF17D0, 0x5995CDD4, 0x3C3BD1CA, 0x091BC498, 0x37419E51, 0x75D75181, 0x5E2D1198}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 196 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1D8EDF2F, 0xB8B1B8C3, 0xD9D156AF, 0x5A60346E, 0x4AB31722, 0xB56A3206, 0x86C60296, 0x629408FF}};
        BigInt<512> var_expected = {.std_words = {0x00B6EAA1, 0x9AE33FE7, 0xFDAC05D9, 0xC7C305A1, 0x0C13CC5F, 0x2D40D18E, 0xE6391156, 0x3706A4AF, 0xDADB45B0, 0xA193F9D3, 0x00793C99, 0xC8DD7C0C, 0x7C3A0A2F, 0x86BD8888, 0x0AF46668, 0x25F5AC7E}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 197 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xC1968A8A, 0x439F65A6, 0x23B361C4, 0xE7FD1389, 0x06AC2908, 0x6C603C9B, 0x5D29A684, 0x3DDBB984}};
        BigInt<512> var_expected = {.std_words = {0xB8B11264, 0xBE5CE462, 0xB352FE34, 0x958F7E9C, 0x622D33D4, 0x51DD0B5C, 0x6E9A8F6E, 0x7D6C9FF8, 0x5EA725CB, 0x4CCDD308, 0xDF484694, 0xF4DED395, 0x66BAA988, 0x69BDB07F, 0x034DD1B4, 0x0EF27300}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 198 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x19247436, 0xECC90560, 0x11B1A4A1, 0x631AAC97, 0x76BC6F75, 0x595763E8, 0x8ECEFCE6, 0x9E521B5D}};
        BigInt<512> var_expected = {.std_words = {0x6FF0FB64, 0x57256863, 0xD2CAF27C, 0x751A6664, 0x81F9D249, 0xCF6DA184, 0xA87DF820, 0x228E1660, 0x5782574D, 0x29CBA8D5, 0x4ED9B174, 0xB4B35C01, 0xD3B954E1, 0x153FB96F, 0x0723DB17, 0x61E9741D}};
        var_res.square(var_a);
        assert_equal(var_expected, var_res, "square 199 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x219F59CB, 0x8EB36BBC, 0xFAF97648, 0x8DD54851, 0x138421AC, 0x0CABA60D, 0x3D4B8A9D, 0x8AF3F856}};
        static const BigInt<256> var_expected = {.std_words = {0x219F59CB, 0x8EB36BBC, 0xFAF97648, 0x8DD54851, 0x138421AC, 0x0CABA60D, 0x3D4B8A9D, 0x8AF3F856}};
        var_res_small.shift_right(var_a, 0);
        assert_equal(var_expected, var_res_small, "shiftRight 200 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x3AC82A41, 0x74C40E10, 0xF94355DA, 0x776B8439, 0x7C0BFEA7, 0x46DECB95, 0x148824F0, 0x1C767846}};
        static const BigInt<256> var_expected = {.std_words = {0x1D641520, 0x3A620708, 0xFCA1AAED, 0xBBB5C21C, 0xBE05FF53, 0x236F65CA, 0x0A441278, 0x0E3B3C23}};
        var_res_small.shift_right(var_a, 1);
        assert_equal(var_expected, var_res_small, "shiftRight 201 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xA7BF0FF8, 0xDF258E12, 0x6D813948, 0x0BEBC6F1, 0xF344BAF7, 0x7ECD00D8, 0xC02D31A8, 0x00A0E277}};
        static const BigInt<256> var_expected = {.std_words = {0x8E12A7BF, 0x3948DF25, 0xC6F16D81, 0xBAF70BEB, 0x00D8F344, 0x31A87ECD, 0xE277C02D, 0x000000A0}};
        var_res_small.shift_right(var_a, 16);
        assert_equal(var_expected, var_res_small, "shiftRight 202 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x119EF73A, 0x846CC463, 0x79A584FC, 0x843C96ED, 0xDF1C8F78, 0x5FB1A117, 0x732174C7, 0xF8E2D75B}};
        static const BigInt<256> var_expected = {.std_words = {0x846CC463, 0x79A584FC, 0x843C96ED, 0xDF1C8F78, 0x5FB1A117, 0x732174C7, 0xF8E2D75B, 0x00000000}};
        var_res_small.shift_right(var_a, 32);
        assert_equal(var_expected, var_res_small, "shiftRight 203 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x049D312F, 0x0B13B60E, 0x8578ACD9, 0xF17770D5, 0x481A49A2, 0x48F1CC74, 0x611181D6, 0x5B4B0AD1}};
        static const BigInt<256> var_expected = {.std_words = {0x8578ACD9, 0xF17770D5, 0x481A49A2, 0x48F1CC74, 0x611181D6, 0x5B4B0AD1, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 64);
        assert_equal(var_expected, var_res_small, "shiftRight 204 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x70CFD231, 0x91C4E4BC, 0xBB7C1F3C, 0xB58B2AE1, 0x5E8F7BBC, 0xCAC5AEAB, 0x43112256, 0x91BED618}};
        static const BigInt<256> var_expected = {.std_words = {0x2725E386, 0xE0F9E48E, 0x59570DDB, 0x7BDDE5AC, 0x2D755AF4, 0x8912B656, 0xF6B0C218, 0x0000048D}};
        var_res_small.shift_right(var_a, 21);
        assert_equal(var_expected, var_res_small, "shiftRight 205 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x823FCAE8, 0x286AEA39, 0x2777D153, 0x8BE2104A, 0x09330DD8, 0xF359B907, 0x2EABAEB3, 0xD7464537}};
        static const BigInt<256> var_expected = {.std_words = {0x5F108251, 0x49986EC4, 0x9ACDC838, 0x755D759F, 0xBA3229B9, 0x00000006, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 93);
        assert_equal(var_expected, var_res_small, "shiftRight 206 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1BBF9216, 0xF5E7626F, 0x669CC6F4, 0x5056B765, 0x278D1EC0, 0x793C2A32, 0xFC33F59F, 0xEDA3E88A}};
        static const BigInt<256> var_expected = {.std_words = {0x6D1F4457, 0x00000007, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 221);
        assert_equal(var_expected, var_res_small, "shiftRight 207 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x6BB77BC4, 0xDB973328, 0xA97DE655, 0x45F8CBF7, 0x877DC935, 0x08270396, 0x6320A40B, 0x13946B9F}};
        static const BigInt<256> var_expected = {.std_words = {0x8D73EC64, 0x00000272, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 211);
        assert_equal(var_expected, var_res_small, "shiftRight 208 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x0CA3F828, 0xA42C0488, 0x689B7080, 0xEEBCA6C0, 0x466BA191, 0xB7827D0F, 0x6746C64A, 0x7BE7E137}};
        static const BigInt<256> var_expected = {.std_words = {0x6ECE8D8C, 0x00F7CFC2, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 199);
        assert_equal(var_expected, var_res_small, "shiftRight 209 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xAAAA59C4, 0xD4B21FC9, 0x2A9F4A32, 0x1595BCE5, 0x2342B98F, 0xCCC6B27A, 0xC1D0AC57, 0xC5A11C64}};
        static const BigInt<256> var_expected = {.std_words = {0xAC57CCC6, 0x1C64C1D0, 0x0000C5A1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 176);
        assert_equal(var_expected, var_res_small, "shiftRight 210 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xCB32192B, 0x4C04C0B0, 0x7CBBD8CF, 0xFD05E6BB, 0x35BDC4FE, 0x40F8834E, 0xA0D84BE3, 0xFAD1960D}};
        static const BigInt<256> var_expected = {.std_words = {0x7F7E82F3, 0xA71ADEE2, 0xF1A07C41, 0x06D06C25, 0x007D68CB, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 105);
        assert_equal(var_expected, var_res_small, "shiftRight 211 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x8D4359E2, 0x452F35E9, 0x32F940AB, 0x51BA9F5D, 0x4F7DE1CB, 0xA4D507E1, 0x4DD7F8C5, 0x6D13CE23}};
        static const BigInt<256> var_expected = {.std_words = {0xD26A83F0, 0xA6EBFC62, 0x3689E711, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 161);
        assert_equal(var_expected, var_res_small, "shiftRight 212 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x1AEACB52, 0x56649537, 0x63CE806C, 0x35D5CFA0, 0x467CEEC6, 0x0739E055, 0x3C5684EB, 0xE9F21AFA}};
        static const BigInt<256> var_expected = {.std_words = {0x495371AE, 0xE806C566, 0x5CFA063C, 0xCEEC635D, 0x9E055467, 0x684EB073, 0x21AFA3C5, 0x00000E9F}};
        var_res_small.shift_right(var_a, 20);
        assert_equal(var_expected, var_res_small, "shiftRight 213 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x243FF85F, 0x4670B5A4, 0x289E9DF2, 0x76AB73BC, 0x806B6E1B, 0x706EA196, 0x3F47DDDC, 0x61A94F13}};
        static const BigInt<256> var_expected = {.std_words = {0x000061A9, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 240);
        assert_equal(var_expected, var_res_small, "shiftRight 214 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x660856C7, 0x640387FE, 0x04352978, 0x1B46C889, 0x150DD52C, 0x132D2FA5, 0x8AFEF51C, 0xC62231C4}};
        static const BigInt<256> var_expected = {.std_words = {0x18C44638, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 227);
        assert_equal(var_expected, var_res_small, "shiftRight 215 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x806BAC87, 0x1CA6668B, 0x7178957C, 0xF472C749, 0xBDBFFF74, 0x9D89E45F, 0x418FF397, 0x728BC44E}};
        static const BigInt<256> var_expected = {.std_words = {0x139063FC, 0x001CA2F1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 202);
        assert_equal(var_expected, var_res_small, "shiftRight 216 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xD85F84F5, 0x5474631E, 0x0A239F47, 0x4C05EAB2, 0x9BCCA59B, 0x8E570278, 0xACBB4212, 0x32C22077}};
        static const BigInt<256> var_expected = {.std_words = {0x72B813C4, 0x65DA1094, 0x961103BD, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 157);
        assert_equal(var_expected, var_res_small, "shiftRight 217 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x2078E520, 0x466FE03C, 0xBA56A41C, 0xA6612DB6, 0x8A13AEB2, 0xE0E4762F, 0x82EDD2F1, 0xA6068C82}};
        static const BigInt<256> var_expected = {.std_words = {0xA320A0BB, 0x00002981, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 210);
        assert_equal(var_expected, var_res_small, "shiftRight 218 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xB86B8B96, 0x10CCF442, 0x62DC40C2, 0x83B27508, 0xE9F16FD0, 0xD74DCC9B, 0x9187DCA7, 0x836FA438}};
        static const BigInt<256> var_expected = {.std_words = {0x00836FA4, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000}};
        var_res_small.shift_right(var_a, 232);
        assert_equal(var_expected, var_res_small, "shiftRight 219 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x10C47694, 0xEA003BDB, 0xA92FA2BA, 0x3F83DAD7, 0x3713C730, 0xCEBDE400, 0x6E2E6850, 0xDC61A6B5}};
        static const BigInt<256> var_expected = {.std_words = {0x7B62188E, 0x575D4007, 0x5AF525F4, 0xE607F07B, 0x8006E278, 0x0A19D7BC, 0xD6ADC5CD, 0x001B8C34}};
        var_res_small.shift_right(var_a, 11);
        assert_equal(var_expected, var_res_small, "shiftRight 220 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xF71BCBF4, 0xB2665471, 0x3C9E7C5F, 0xB81A855C, 0x13A4ABFB, 0x9132F751, 0xD9C5903E, 0xA3DD48F1}};
        static const BigInt<256> var_expected = {.std_words = {0xFB8DE5FA, 0xD9332A38, 0x1E4F3E2F, 0xDC0D42AE, 0x89D255FD, 0x48997BA8, 0xECE2C81F, 0x51EEA478}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 221 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9C19B784, 0x8A3A3F78, 0x6346ED56, 0xDB96596C, 0xB7C30E3B, 0xFF0AF04A, 0x8DEDF2C1, 0x596051F0}};
        static const BigInt<256> var_expected = {.std_words = {0x4E0CDBC2, 0x451D1FBC, 0x31A376AB, 0xEDCB2CB6, 0x5BE1871D, 0xFF857825, 0x46F6F960, 0x2CB028F8}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 222 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x84EBBE1C, 0xC610ADEA, 0xDCAFD10E, 0x0726C9F7, 0x2A1C9934, 0x23BAC211, 0xF5D7D333, 0x8C16604F}};
        static const BigInt<256> var_expected = {.std_words = {0x4275DF0E, 0x630856F5, 0xEE57E887, 0x039364FB, 0x950E4C9A, 0x91DD6108, 0xFAEBE999, 0x460B3027}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 223 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x5425281D, 0x86B78B58, 0x64790703, 0x03F9F921, 0x0E9D2640, 0x5433ED49, 0x1CD4842E, 0xC9892F53}};
        static const BigInt<256> var_expected = {.std_words = {0x2A12940E, 0xC35BC5AC, 0xB23C8381, 0x01FCFC90, 0x874E9320, 0x2A19F6A4, 0x8E6A4217, 0x64C497A9}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 224 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x135F366C, 0x5E24A010, 0x806E3877, 0xEB755E34, 0x2A7C359F, 0x1EC2B339, 0x95D95FAA, 0xB18B128B}};
        static const BigInt<256> var_expected = {.std_words = {0x09AF9B36, 0xAF125008, 0x40371C3B, 0xF5BAAF1A, 0x953E1ACF, 0x0F61599C, 0xCAECAFD5, 0x58C58945}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 225 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0xAEDD19B9, 0xD86EB05C, 0xF7DB8174, 0xAD0E7F9E, 0xE655F3F9, 0xBE5C385F, 0xF4949A76, 0x7AA4A58F}};
        static const BigInt<256> var_expected = {.std_words = {0x576E8CDC, 0x6C37582E, 0x7BEDC0BA, 0xD6873FCF, 0xF32AF9FC, 0x5F2E1C2F, 0xFA4A4D3B, 0x3D5252C7}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 226 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x75CBDA31, 0xF09A020A, 0x52F40120, 0x8F67B8CB, 0xD2DD9DD7, 0xA7C63991, 0x5284BE2F, 0x6DD1CF43}};
        static const BigInt<256> var_expected = {.std_words = {0x3AE5ED18, 0x784D0105, 0xA97A0090, 0xC7B3DC65, 0xE96ECEEB, 0xD3E31CC8, 0xA9425F17, 0x36E8E7A1}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 227 ");
    }
    {
        static const BigInt<256> var_a = {.std_words = {0x9C0043B9, 0x9633FA85, 0x6344FDBA, 0xA7CD27DB, 0x1F1F1933, 0xFF82A46A, 0xCD23583D, 0x6993ACB4}};
        static const BigInt<256> var_expected = {.std_words = {0xCE0021DC, 0x4B19FD42, 0xB1A27EDD, 0xD3E693ED, 0x0F8F8C99, 0xFFC15235, 0x6691AC1E, 0x34C9D65A}};
        var_res_small.shift_right_in_word<1>(var_a);
        assert_equal(var_expected, var_res_small, "shiftRightOne 228 ");
    }
    if (passed) {
        printf("All tests PASSed.\n");
    } else {
        printf("Some tests FAILed.\n");
    }
}
