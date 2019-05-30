#include <stdio.h>
#include <string.h>
#include "bls12_381/fr.hpp"
#include "bls12_381/fq.hpp"
#include "bls12_381/fq2.hpp"
#include "bls12_381/fq6.hpp"
#include "bls12_381/fq12.hpp"
#include "bls12_381/curve.hpp"
#include "bls12_381/pairing.hpp"
#include "bls12_381/wnaf.hpp"

using namespace embedded_pairing::bls12_381;
using embedded_pairing::core::BigInt;

extern "C" {
    void random_bytes(void* buffer, size_t len);
    uint64_t current_time_nanos(void);
}

#if defined(__ARM_ARCH_6M__)
constexpr int few_iters = 3;
constexpr int std_iters = 100;
constexpr int many_iters = 1000;
#else
constexpr int few_iters = 10;
constexpr int std_iters = 1000;
constexpr int many_iters = 1000000;
#endif

/* Allows us to pass brace-enclosed initializer lists to macros. */
#define ARR(...) __VA_ARGS__

const char* test_fr_legendre(void) {
    if (Fr::one.legendre() != 1) {
        return "FAIL (one)";
    }
    if (Fr::zero.legendre() != 0) {
        return "FAIL (zero)";
    }

    Fr t1 = {{{{.std_words = {0xcd5664da, 0xdbc5349, 0x6e3ae29d, 0x8ac5b629, 0xfeceaa3b, 0x127cb819, 0x3867191, 0x3a6b21fb}}}}};
    if (t1.legendre() != 1) {
        return "FAIL (t1)";
    }

    Fr t2 = {{{{.std_words = {0xd047c045, 0x96341aef, 0x500a4d65, 0x9b5f4254, 0xb68ac240, 0x1ee08223, 0x5c0ec7c6, 0x31d9cd54}}}}};
    if (t2.legendre() != -1) {
        return "FAIL (t2)";
    }

    return "PASS";
}
#define TEST_FR_ADD(name, op1, op2, sum) \
    do { \
        Fr a = op1; \
        Fr b = op2; \
        Fr c; \
        c.add(a, b); \
        Fr expected_sum = sum; \
        if (!Fr::equal(c, expected_sum)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fr_add(void) {
    /* Test that adding zero has no effect. */
    TEST_FR_ADD("t1",
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}),
             ARR({{{ BigInt<256>::zero }}}),
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}));

    /* Add one and test for the result. */
    TEST_FR_ADD("t2",
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}),
             ARR({{{ BigInt<256>::one }}}),
             ARR({{{{.std_words = {0x6d580766, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}));

    /* Add another random number that exercises the reduction. */
    TEST_FR_ADD("t3",
             ARR({{{{.std_words = {0x6d580766, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}),
             ARR({{{{.std_words = {0x44f7dc79, 0x946f4359, 0x533a9b9b, 0xb55e7ee6, 0x2f6194ca, 0x1e43b84c, 0x25463496, 0x58717ab5}}}}}),
             ARR({{{{.std_words = {0xb24fe3de, 0xd7ec2abb, 0x7d0d62f7, 0x35cdf7ae, 0x477cd0e9, 0xd899557c, 0xc43de018, 0x3371b52b}}}}}));

    /* Add one to (r - 1) and test for the result. */
    TEST_FR_ADD("t4",
             ARR({{{{.std_words = {0x0, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x9a1d805, 0x3339d808, 0x299d7d48, 0x73eda753}}}}}),
             ARR({{{ BigInt<256>::one }}}),
             ARR({{{ BigInt<256>::zero }}}));

    /* Add a random number to another one such that the result is r - 1. */
    TEST_FR_ADD("t5",
             ARR({{{{.std_words = {0xdccb6190, 0xade5adac, 0x27db3ccd, 0xaa21ee0f, 0x4ae39086, 0x2550f470, 0xe7c5ba27, 0x591d1902}}}}}),
             ARR({{{{.std_words = {0x23349e70, 0x521a5252, 0xd8231f31, 0xa99bb5f3, 0xbebe477e, 0xde8e397, 0x41d7c321, 0x1ad08e50}}}}}),
             ARR({{{{.std_words = {0x0, 0xffffffff, 0xfffe5bfe, 0x53bda402, 0x9a1d805, 0x3339d808, 0x299d7d48, 0x73eda753}}}}}));

    /* Generate a + b and ensure (a + b) + c == a + (b + c). */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        Fr b;
        Fr c;
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fr tmp1;
        Fr tmp2;
        Fr tmp3;

        tmp1.add(a, b);
        tmp1.add(tmp1, c);
        tmp2.add(b, c);
        tmp3.copy(tmp2);
        tmp2.add(a, tmp3);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL (associativity)";
        }
    }

    return "PASS";
}
#define TEST_FR_SUB(name, op1, op2, diff) \
    do { \
        Fr a = op1; \
        Fr b = op2; \
        Fr c; \
        c.subtract(a, b); \
        Fr expected_diff = diff; \
        if (!Fr::equal(c, expected_diff)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fr_sub(void) {
    /* Test arbitrary subtraction that tests reduction. */
    TEST_FR_SUB("t1",
             ARR({{{{.std_words = {0x6f735a2b, 0x6a68c64b, 0xfe0a1972, 0xd5f4d143, 0x29267c62, 0x37c17f38, 0x1f30915c, 0xa2f3739}}}}}),
             ARR({{{{.std_words = {0xdccb6190, 0xade5adac, 0x27db3ccd, 0xaa21ee0f, 0x4ae39086, 0x2550f470, 0xe7c5ba27, 0x591d1902}}}}}),
             ARR({{{{.std_words = {0x92a7f89c, 0xbc83189d, 0xd62d38a3, 0x7f908737, 0xe7e4c3e1, 0x45aa62cf, 0x6108547d, 0x24ffc589}}}}}));

    /* Test the opposite subtraction which doesn't test reduction. */
    TEST_FR_SUB("t2",
             ARR({{{{.std_words = {0xdccb6190, 0xade5adac, 0x27db3ccd, 0xaa21ee0f, 0x4ae39086, 0x2550f470, 0xe7c5ba27, 0x591d1902}}}}}),
             ARR({{{{.std_words = {0x6f735a2b, 0x6a68c64b, 0xfe0a1972, 0xd5f4d143, 0x29267c62, 0x37c17f38, 0x1f30915c, 0xa2f3739}}}}}),
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}));

    /* Test for sensible results with zero. */
    TEST_FR_SUB("t3",
             ARR({{{ BigInt<256>::zero }}}),
             ARR({{{ BigInt<256>::zero }}}),
             ARR({{{ BigInt<256>::zero }}}));

    /* Test for sensible results with zero. */
    TEST_FR_SUB("t4",
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}),
             ARR({{{ BigInt<256>::zero }}}),
             ARR({{{{.std_words = {0x6d580765, 0x437ce761, 0x29d1235b, 0xd42d1ccb, 0x21bd1423, 0xed8f7538, 0xc89528ca, 0x4eede1c9}}}}}));

    /* Ensure that (a - b) + (b - a) == 0. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        Fr b;
        a.random(random_bytes);
        b.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp1.subtract(a, b);
        tmp2.subtract(b, a);
        tmp1.add(tmp1, tmp2);

        if (!Fr::equal(tmp1, Fr::zero)) {
            return "FAIL (reverse)";
        }
    }

    return "PASS";
}

const char* test_fr_mul(void) {
    {
        Fr a = {{{{.std_words = {0xaeefc81a, 0x6b7e9b8f, 0xf348ba42, 0xe30a8463, 0xa8279c9c, 0xeff3cb67, 0xbd7c774d, 0x3d303651}}}}};
        Fr b = {{{{.std_words = {0xbc35ebeb, 0x13ae28e3, 0x75cae2c, 0xa10f4488, 0x853c3b5d, 0x8160e95a, 0x561a841d, 0x5ae3f03b}}}}};
        Fr c;
        c.multiply(a, b);
        Fr expected_prod = {{{{.std_words = {0xce710f71, 0x23717213, 0x3a16e1af, 0xdbee1fe5, 0xc2a48000, 0xf565d3e1, 0xe75df9d7, 0x4426507e}}}}};
        if (!Fr::equal(c, expected_prod)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that (a * b) * c = a * (b * c). */
    for (int i = 0; i != many_iters; i++) {
        Fr a;
        Fr b;
        Fr c;
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp1.multiply(a, b);
        tmp1.multiply(tmp1, c);
        tmp2.multiply(b, c);
        tmp2.multiply(a, tmp2);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL (associativity)";
        }
    }

    /* Ensure that r * (a + b + c) = r * a + r * b + r * c */
    for (int i = 0; i != many_iters; i++) {
        Fr r;
        Fr a;
        Fr b;
        Fr c;
        r.random(random_bytes);
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fr tmp1;
        Fr tmp2;
        Fr tmp3;

        tmp1.add(a, b);
        tmp1.add(tmp1, c);
        tmp1.multiply(r, tmp1);

        tmp2.multiply(r, a);
        tmp3.multiply(r, b);
        tmp2.add(tmp2, tmp3);
        tmp3.multiply(r, c);
        tmp2.add(tmp2, tmp3);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL (distributivity)";
        }
    }

    return "PASS";
}

const char* test_fr_squaring(void) {
    {
        Fr a = {{{{.std_words = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x299d7d47, 0x73eda753}}}}};
        Fr c;
        c.multiply(a, a);
        Fr expected_square;
        BigInt<256> expected_square_int = {.std_words = {0xbde077b8, 0xc0d698e7, 0x79e76ec2, 0xb79a3105, 0xa9af4e5f, 0xac1da8d0, 0x9bf23e97, 0x13f629c4}};
        expected_square.set(expected_square_int);
        if (!Fr::equal(c, expected_square)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that (a * a) = a ^ 2. */
    for (int i = 0; i != many_iters; i++) {
        Fr a;
        a.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp1.multiply(a, a);
        tmp2.square(a);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL (definition)";
        }
    }

    return "PASS";
}

const char* test_fr_inverse(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        a.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        fp_inverse(tmp2, a);
        tmp1.multiply(a, tmp2);

        if (!Fr::equal(tmp1, Fr::one)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fr_double(void) {
    /* Ensure that a + a = 2a. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        a.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp1.add(a, a);
        tmp2.multiply2(a);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fr_negate(void) {
    /* Ensure that a + (-a) = 0. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        a.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp2.negate(a);
        tmp1.add(a, tmp2);

        if (!Fr::equal(tmp1, Fr::zero)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fr_pow(void) {
    /* Compare exponentiation with small powers to repeated multiplication. */
    Fr a;
    a.random(random_bytes);

    BigInt<256> exponent = BigInt<256>::zero;
    Fr tmp1 = Fr::one;

    for (int i = 0; i != std_iters; i++) {
        Fr tmp2;

        exponentiate(tmp2, a, exponent);

        if (!Fr::equal(tmp1, tmp2)) {
            return "FAIL (repeated multiplication)";
        }

        tmp1.multiply(tmp1, a);
        exponent.add(exponent, BigInt<256>::one);
    }

    /* Exponentiation by the modulus does nothing. */
    for (int i = 0; i != std_iters; i++) {
        a.random(random_bytes);
        exponentiate(tmp1, a, fr_modulus);
        if (!Fr::equal(tmp1, a)) {
            return "FAIL (modulus)";
        }
    }

    return "PASS";
}

const char* test_fr_sqrt(void) {
    {
        Fr res;
        res.square_root(Fr::zero);
        if (!Fr::equal(res, Fr::zero)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that sqrt(a)^2 == a. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;

        do {
            a.random(random_bytes);
        } while (a.legendre() != 1);

        Fr tmp1;
        Fr tmp2;

        tmp2.square_root(a);
        tmp1.square(tmp2);

        if (!Fr::equal(tmp1, a)) {
            return "FAIL (square of sqrt)";
        }
    }

    /* Ensure that sqrt(a^2) is either a or -a. */
    for (int i = 0; i != std_iters; i++) {
        Fr a;
        a.random(random_bytes);

        Fr tmp1;
        Fr tmp2;

        tmp2.square(a);
        tmp1.square_root(tmp2);

        if (!Fr::equal(tmp1, a)) {
            tmp2.negate(tmp1);
            if (!Fr::equal(tmp2, a)) {
                return "FAIL (sqrt of square)";
            }
        }
    }

    return "PASS";
}

void test_bls12_381_fr(void) {
    printf("Fr:\n");
    printf("Legendre...\t\t%s\n", test_fr_legendre());
    printf("Addition...\t\t%s\n", test_fr_add());
    printf("Subtraction...\t\t%s\n", test_fr_sub());
    printf("Multiplication...\t%s\n", test_fr_mul());
    printf("Squaring...\t\t%s\n", test_fr_squaring());
    printf("Inverse...\t\t%s\n", test_fr_inverse());
    printf("Double...\t\t%s\n", test_fr_double());
    printf("Negate...\t\t%s\n", test_fr_negate());
    printf("Exponentiate...\t\t%s\n", test_fr_pow());
    printf("Square Root...\t\t%s\n", test_fr_sqrt());
    printf("\n");
}

const char* test_fq_legendre(void) {
    if (Fq::one.legendre() != 1) {
        return "FAIL (one)";
    }
    if (Fq::zero.legendre() != 0) {
        return "FAIL (zero)";
    }

    Fq two;
    const BigInt<384> two_const = {.std_words = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    two.set(two_const);
    if (two.legendre() != -1) {
        return "FAIL (two)";
    }

    Fq four;
    const BigInt<384> four_const = {.std_words = {4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    four.set(four_const);
    if (four.legendre() != 1) {
        return "FAIL (four)";
    }

    Fq t1 = {{{{.std_words = {0x49778642, 0x52a112f2, 0x89b7991f, 0xd0bedb9, 0x1aa63c05, 0xdad3b668, 0x4721b283, 0xf2efc0bb, 0x18c24733, 0x6057a98f, 0x122889e4, 0x1022c2fd}}}}};
    if (t1.legendre() != -1) {
        return "FAIL (t1)";
    }

    Fq t2 = {{{{.std_words = {0x53a96c74, 0x6dae594e, 0xba64b37b, 0x19b16ca9, 0xa59bfc68, 0x5c764661, 0x9b31c60a, 0xaa346e, 0xd87a9fa9, 0x346059f9, 0xbfd5c88b, 0x1d61ac6}}}}};
    if (t2.legendre() != 1) {
        return "FAIL (t2)";
    }

    return "PASS";
}
#define TEST_FQ_ADD(name, op1, op2, sum) \
    do { \
        Fq a = op1; \
        Fq b = op2; \
        Fq c; \
        c.add(a, b); \
        Fq expected_sum = sum; \
        if (!Fq::equal(c, expected_sum)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fq_add(void) {
    /* Test that adding zero has no effect. */
    TEST_FQ_ADD("t1",
             ARR({{{{.std_words = {0x1df92b69, 0x62443482, 0x4fd2e2ea, 0x503260c0, 0xd16e8ce, 0xd9df726e, 0xfd5dfaeb, 0xfbcb39ad, 0xc88b112, 0x86b8a22b, 0x9e4201b, 0x165a2ed8}}}}}),
             ARR({{{ BigInt<384>::zero }}}),
             ARR({{{{.std_words = {0x1df92b69, 0x62443482, 0x4fd2e2ea, 0x503260c0, 0xd16e8ce, 0xd9df726e, 0xfd5dfaeb, 0xfbcb39ad, 0xc88b112, 0x86b8a22b, 0x9e4201b, 0x165a2ed8}}}}}));

    /* Add one and test for the result. */
    TEST_FQ_ADD("t2",
             ARR({{{{.std_words = {0x1df92b69, 0x62443482, 0x4fd2e2ea, 0x503260c0, 0xd16e8ce, 0xd9df726e, 0xfd5dfaeb, 0xfbcb39ad, 0xc88b112, 0x86b8a22b, 0x9e4201b, 0x165a2ed8}}}}}),
             ARR({{{ BigInt<384>::one }}}),
             ARR({{{{.std_words = {0x1df92b6a, 0x62443482, 0x4fd2e2ea, 0x503260c0, 0xd16e8ce, 0xd9df726e, 0xfd5dfaeb, 0xfbcb39ad, 0xc88b112, 0x86b8a22b, 0x9e4201b, 0x165a2ed8}}}}}));

    /* Add another random number that exercises the reduction. */
    TEST_FQ_ADD("t3",
             ARR({{{{.std_words = {0x1df92b6a, 0x62443482, 0x4fd2e2ea, 0x503260c0, 0xd16e8ce, 0xd9df726e, 0xfd5dfaeb, 0xfbcb39ad, 0xc88b112, 0x86b8a22b, 0x9e4201b, 0x165a2ed8}}}}}),
             ARR({{{{.std_words = {0xa7a648d8, 0x374d8f8e, 0xbb8bfa9b, 0xe318bb0e, 0xa95b400, 0x613d996f, 0xb7e4fef1, 0x9fac233c, 0x2d253c52, 0x67e4755, 0x7edf25da, 0x5c31b22}}}}}),
             ARR({{{{.std_words = {0xc59fc997, 0xdf92c410, 0x5a0add85, 0x149f1bd0, 0x20fba6ab, 0xd3ec393c, 0xc1bde71d, 0x37001165, 0xf662408e, 0x421b41c9, 0x4f435f5b, 0x21c3810}}}}}));

    /* Add one to (q - 1) and test for the result. */
    TEST_FQ_ADD("t4",
             ARR({{{{.std_words = {0xffffaaaa, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea}}}}}),
             ARR({{{ BigInt<384>::one }}}),
             ARR({{{ BigInt<384>::zero }}}));

    /* Add a random number to another one such that the result is r - 1. */
    TEST_FQ_ADD("t5",
             ARR({{{{.std_words = {0x10efc95b, 0x531221a4, 0x27e9717, 0x72819306, 0x7068b746, 0x5ecefb93, 0x6feaefd7, 0x97de59cd, 0x58644588, 0xdc35c511, 0xc04f2100, 0xb2d176}}}}}),
             ARR({{{{.std_words = {0xef0fe14f, 0x66ecde5b, 0xaed568e8, 0xac2a6cf8, 0x86483edd, 0x861d70d, 0x839a22e8, 0xcc98f1b7, 0xeae7674e, 0x6ee5e2a4, 0x7930c599, 0x194e4073}}}}}),
             ARR({{{{.std_words = {0xffffaaaa, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea}}}}}));

    /* Generate a + b and ensure (a + b) + c == a + (b + c). */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        Fq b;
        Fq c;
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fq tmp1;
        Fq tmp2;
        Fq tmp3;

        tmp1.add(a, b);
        tmp1.add(tmp1, c);
        tmp2.add(b, c);
        tmp3.copy(tmp2);
        tmp2.add(a, tmp3);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL (associativity)";
        }
    }

    return "PASS";
}
#define TEST_FQ_SUB(name, op1, op2, diff) \
    do { \
        Fq a = op1; \
        Fq b = op2; \
        Fq c; \
        c.subtract(a, b); \
        Fq expected_diff = diff; \
        if (!Fq::equal(c, expected_diff)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fq_sub(void) {
    /* Test arbitrary subtraction that tests reduction. */
    TEST_FQ_SUB("t1",
             ARR({{{{.std_words = {0x10efc95b, 0x531221a4, 0x27e9717, 0x72819306, 0x7068b746, 0x5ecefb93, 0x6feaefd7, 0x97de59cd, 0x58644588, 0xdc35c511, 0xc04f2100, 0xb2d176}}}}}),
             ARR({{{{.std_words = {0x877e4ada, 0x98910d20, 0x13f4b8ba, 0x940c9830, 0x8345ba33, 0xf677dc9b, 0x7f577eba, 0xbef2ce6b, 0xc3222c44, 0xe1ae288a, 0x2790806, 0x5968bb6}}}}}),
             ARR({{{{.std_words = {0x8971292c, 0x74801483, 0x9fddde5c, 0xfd20fad4, 0xe3d3f336, 0xcf87f198, 0xe41883db, 0x3d62d6e6, 0xd88dc61b, 0x45a3443c, 0xf755ff94, 0x151d57aa}}}}}));

    /* Test the opposite subtraction which doesn't test reduction. */
    TEST_FQ_SUB("t2",
             ARR({{{{.std_words = {0x877e4ada, 0x98910d20, 0x13f4b8ba, 0x940c9830, 0x8345ba33, 0xf677dc9b, 0x7f577eba, 0xbef2ce6b, 0xc3222c44, 0xe1ae288a, 0x2790806, 0x5968bb6}}}}}),
             ARR({{{{.std_words = {0x10efc95b, 0x531221a4, 0x27e9717, 0x72819306, 0x7068b746, 0x5ecefb93, 0x6feaefd7, 0x97de59cd, 0x58644588, 0xdc35c511, 0xc04f2100, 0xb2d176}}}}}),
             ARR({{{{.std_words = {0x768e817f, 0x457eeb7c, 0x117621a3, 0x218b052a, 0x12dd02ed, 0x97a8e108, 0xf6c8ee3, 0x2714749e, 0x6abde6bc, 0x5786379, 0x4229e706, 0x4e3ba3f}}}}}));

    /* Test for sensible results with zero. */
    TEST_FQ_SUB("t3",
             ARR({{{ BigInt<384>::zero }}}),
             ARR({{{ BigInt<384>::zero }}}),
             ARR({{{ BigInt<384>::zero }}}));

    /* Test for sensible results with zero. */
    TEST_FQ_SUB("t4",
             ARR({{{{.std_words = {0x877e4ada, 0x98910d20, 0x13f4b8ba, 0x940c9830, 0x8345ba33, 0xf677dc9b, 0x7f577eba, 0xbef2ce6b, 0xc3222c44, 0xe1ae288a, 0x2790806, 0x5968bb6}}}}}),
             ARR({{{ BigInt<384>::zero }}}),
             ARR({{{{.std_words = {0x877e4ada, 0x98910d20, 0x13f4b8ba, 0x940c9830, 0x8345ba33, 0xf677dc9b, 0x7f577eba, 0xbef2ce6b, 0xc3222c44, 0xe1ae288a, 0x2790806, 0x5968bb6}}}}}));

    /* Ensure that (a - b) + (b - a) == 0. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        Fq b;
        a.random(random_bytes);
        b.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp1.subtract(a, b);
        tmp2.subtract(b, a);
        tmp1.add(tmp1, tmp2);

        if (!Fq::equal(tmp1, Fq::zero)) {
            return "FAIL (reverse)";
        }
    }

    return "PASS";
}

const char* test_fq_mul(void) {
    {
        Fq a = {{{{.std_words = {0x20aa8a, 0xcc620000, 0x1dd8001a, 0x42280080, 0x9041c62c, 0x7f4f5e61, 0xc70ed2ba, 0x8a55171a, 0x3d07d58b, 0x3f69cc3a, 0xfd09b8ef, 0xb972455}}}}};
        Fq b = {{{{.std_words = {0x30ffcf, 0x32930000, 0x2cc40028, 0x633c00c0, 0x5862a942, 0xbef70d92, 0x2a963c17, 0x4f7fa2a8, 0x5b8bc051, 0xdf1eb257, 0xfb8e9566, 0x1162b680}}}}};
        Fq c;
        c.multiply(a, b);
        Fq expected_prod = {{{{.std_words = {0x1ebfe14, 0x9dc40000, 0x97b00193, 0x28500789, 0xabb4d7bf, 0xa8197f1, 0xf4bfe871, 0xc0309573, 0xffaf7620, 0xf48d0923, 0x7a926e66, 0x11d4b58c}}}}};
        if (!Fq::equal(c, expected_prod)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that (a * b) * c = a * (b * c). */
    for (int i = 0; i != many_iters; i++) {
        Fq a;
        Fq b;
        Fq c;
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp1.multiply(a, b);
        tmp1.multiply(tmp1, c);
        tmp2.multiply(b, c);
        tmp2.multiply(a, tmp2);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL (associativity)";
        }
    }

    /* Ensure that r * (a + b + c) = r * a + r * b + r * c */
    for (int i = 0; i != many_iters; i++) {
        Fq r;
        Fq a;
        Fq b;
        Fq c;
        r.random(random_bytes);
        a.random(random_bytes);
        b.random(random_bytes);
        c.random(random_bytes);

        Fq tmp1;
        Fq tmp2;
        Fq tmp3;

        tmp1.add(a, b);
        tmp1.add(tmp1, c);
        tmp1.multiply(r, tmp1);

        tmp2.multiply(r, a);
        tmp3.multiply(r, b);
        tmp2.add(tmp2, tmp3);
        tmp3.multiply(r, c);
        tmp2.add(tmp2, tmp3);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL (distributivity)";
        }
    }

    return "PASS";
}

const char* test_fq_squaring(void) {
    {
        Fq a = {{{{.std_words = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x19ffffff}}}}};
        Fq c;
        c.multiply(a, a);
        Fq expected_square;
        BigInt<384> expected_square_int = {.std_words = {0x7dfbbb86, 0x1cfb28fe, 0x31577a59, 0x24cbe17, 0xc120e66e, 0xcce1d4ed, 0xb4e15b27, 0xdc05c659, 0x802c6a23, 0x79361e5a, 0xd51b9a6f, 0x24bcbe5}};
        expected_square.set(expected_square_int);
        if (!Fq::equal(c, expected_square)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that (a * a) = a ^ 2. */
    for (int i = 0; i != many_iters; i++) {
        Fq a;
        a.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp1.multiply(a, a);
        tmp2.square(a);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL (definition)";
        }
    }

    return "PASS";
}

const char* test_fq_inverse(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        a.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        fp_inverse(tmp2, a);
        tmp1.multiply(a, tmp2);

        if (!Fq::equal(tmp1, Fq::one)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq_double(void) {
    /* Ensure that a + a = 2a. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        a.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp1.add(a, a);
        tmp2.multiply2(a);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq_negate(void) {
    /* Ensure that a + (-a) = 0. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        a.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp2.negate(a);
        tmp1.add(a, tmp2);

        if (!Fq::equal(tmp1, Fq::zero)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq_pow(void) {
    /* Compare exponentiation with small powers to repeated multiplication. */
    Fq a;
    a.random(random_bytes);

    BigInt<384> exponent = BigInt<384>::zero;
    Fq tmp1 = Fq::one;

    for (int i = 0; i != std_iters; i++) {
        Fq tmp2;

        exponentiate(tmp2, a, exponent);

        if (!Fq::equal(tmp1, tmp2)) {
            return "FAIL (repeated multiplication)";
        }

        tmp1.multiply(tmp1, a);
        exponent.add(exponent, BigInt<384>::one);
    }

    /* Exponentiation by the modulus does nothing. */
    for (int i = 0; i != std_iters; i++) {
        a.random(random_bytes);
        exponentiate(tmp1, a, fq_modulus);
        if (!Fq::equal(tmp1, a)) {
            return "FAIL (modulus)";
        }
    }

    return "PASS";
}

const char* test_fq_sqrt(void) {
    {
        Fq res;
        res.square_root(Fq::zero);
        if (!Fq::equal(res, Fq::zero)) {
            return "FAIL (t1)";
        }
    }

    /* Ensure that sqrt(a)^2 == a. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;

        do {
            a.random(random_bytes);
        } while (a.legendre() != 1);

        Fq tmp1;
        Fq tmp2;

        tmp2.square_root(a);
        tmp1.square(tmp2);

        if (!Fq::equal(tmp1, a)) {
            return "FAIL (square of sqrt)";
        }
    }

    /* Ensure that sqrt(a^2) is either a or -a. */
    for (int i = 0; i != std_iters; i++) {
        Fq a;
        a.random(random_bytes);

        Fq tmp1;
        Fq tmp2;

        tmp2.square(a);
        tmp1.square_root(tmp2);

        if (!Fq::equal(tmp1, a)) {
            tmp2.negate(a);
            if (!Fq::equal(tmp1, tmp2)) {
                return "FAIL (sqrt of square)";
            }
        }
    }

    return "PASS";
}

void test_bls12_381_fq(void) {
    printf("Fq:\n");
    printf("Legendre...\t\t%s\n", test_fq_legendre());
    printf("Addition...\t\t%s\n", test_fq_add());
    printf("Subtraction...\t\t%s\n", test_fq_sub());
    printf("Multiplication...\t%s\n", test_fq_mul());
    printf("Squaring...\t\t%s\n", test_fq_squaring());
    printf("Inverse...\t\t%s\n", test_fq_inverse());
    printf("Double...\t\t%s\n", test_fq_double());
    printf("Negate...\t\t%s\n", test_fq_negate());
    printf("Exponentiate...\t\t%s\n", test_fq_pow());
    printf("Square Root...\t\t%s\n", test_fq_sqrt());
    printf("\n");
}

#define TEST_FQ2_SQUARING(name, op_c0, op_c1, res_c0, res_c1) \
    do { \
        Fq2 a; \
        BigInt<384> op1_c0_bi = op_c0; \
        BigInt<384> op1_c1_bi = op_c1; \
        a.c0.set(op1_c0_bi); \
        a.c1.set(op1_c1_bi); \
        Fq2 c; \
        c.square(a); \
        Fq2 expected; \
        BigInt<384> sum_c0_bi = res_c0; \
        BigInt<384> sum_c1_bi = res_c1; \
        expected.c0.set(sum_c0_bi); \
        expected.c1.set(sum_c1_bi); \
        if (!Fq2::equal(c, expected)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fq2_squaring(void) {
    TEST_FQ2_SQUARING("u + 1",
                      BigInt<384>::one,
                      BigInt<384>::one,
                      BigInt<384>::zero,
                      ARR({.std_words = {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}));

    TEST_FQ2_SQUARING("u",
                      BigInt<384>::zero,
                      BigInt<384>::one,
                      ARR({.std_words = {0xffffaaaa, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea }}),
                      BigInt<384>::zero);

    TEST_FQ2_SQUARING("t0",
                      ARR({.std_words = {0xbbf8b598, 0x9c2c6309, 0x6536f602, 0x4eef5c94, 0x6fb6a6bd, 0x90e34aab, 0x4e58ae7c, 0xf7f295a9, 0x1c3fbe5e, 0x41b76dcc, 0xa1d8e042, 0x7080c5f}}),
                      ARR({.std_words = {0xc870a4ab, 0x38f473b3, 0x77c8c7e5, 0x6ad32911, 0x11a4353e, 0xdac5a4c9, 0x604137a0, 0xbfb99020, 0xbe815407, 0xfc58a7b7, 0x75250a21, 0x10d1615e}}),
                      ARR({.std_words = {0x538bcf68, 0xf262c28c, 0xae1073ba, 0xb9f2a66e, 0xfad67ae0, 0xdc46ab8, 0x618da176, 0xcb674157, 0x93c3d327, 0x4cf17b58, 0x69c43361, 0x7eac813}}),
                      ARR({.std_words = {0x8e980cf8, 0xc1579cf5, 0x2dd54d98, 0xa23eb7e1, 0xe4cec7aa, 0xe75138bc, 0x5a9689e1, 0x38d0d727, 0x42779a65, 0x739c9830, 0x8a8db994, 0x1542a61c}}));

    return "PASS";
}

const char* test_fq2_mul(void) {
    Fq2 a;
    BigInt<384> op1_c0_bi = {.std_words = {0xe1461f03, 0x85c9f989, 0x3449a1d6, 0xa2e33c33, 0x4a7354a3, 0x41e46115, 0x84d7532e, 0x9ee53e7e, 0xd97afb45, 0x1c202d8e, 0x53e2516f, 0x51d3f92}};
    BigInt<384> op1_c1_bi = {.std_words = {0x511aedcf, 0xa7348a8b, 0x8176b319, 0x143c215d, 0xc09b8903, 0x4cc48081, 0x9a5158be, 0x9533e4a, 0x676d65f9, 0x7a5e1ecb, 0x6656b008, 0x180c3ee4}};
    a.c0.set(op1_c0_bi);
    a.c1.set(op1_c1_bi);
    Fq2 b;
    BigInt<384> op2_c0_bi = {.std_words = {0x805f537e, 0xe21f9169, 0x179c285d, 0xfc87e62e, 0xbe07a531, 0x27ece175, 0xc23e430, 0xcd460f9f, 0x92bfa409, 0x6c91102, 0xeb8af83e, 0x2c93a72}};
    BigInt<384> op2_c1_bi = {.std_words = {0x6d8992d4, 0x4b1c3f93, 0x6dba4c8a, 0x1d2a7291, 0x658d1e5f, 0x8871c508, 0x35a752ae, 0x57a06d31, 0xc565096d, 0x634cd3c6, 0xd4e93558, 0x19e17334}};
    b.c0.set(op2_c0_bi);
    b.c1.set(op2_c1_bi);
    Fq2 c;
    c.multiply(a, b);
    Fq2 expected;
    BigInt<384> prod_c0_bi = {.std_words = {0x6360c7e4, 0x95b5127e, 0x19a6937e, 0xde29c31a, 0xcf5a39bc, 0xf61a96da, 0x84ee5f78, 0x5511fe4d, 0xd92f9963, 0x5310a202, 0x166e5399, 0x1751afbe}};
    BigInt<384> prod_c1_bi = {.std_words = {0xd630117a, 0x84af0e1b, 0xda2c2aa7, 0x6c63cd4, 0xe883d40, 0x5ba6e543, 0x79c275ee, 0xc9751065, 0xce4c5083, 0x33a9ac82, 0xc201589d, 0x1ef1a36}};
    expected.c0.set(prod_c0_bi);
    expected.c1.set(prod_c1_bi);
    if (!Fq2::equal(c, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_fq2_add(void) {
    Fq2 a;
    BigInt<384> op1_c0_bi = {.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}};
    BigInt<384> op1_c1_bi = {.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}};
    a.c0.set(op1_c0_bi);
    a.c1.set(op1_c1_bi);
    Fq2 b;
    BigInt<384> op2_c0_bi = {.std_words = {0x8dc70ef2, 0x619a02d7, 0x119e33e8, 0xb93adfc9, 0x9f0dca12, 0x4bf0b99a, 0x42a6318f, 0x3b88899a, 0xfa82a49d, 0x986a4a62, 0xa26027f5, 0x13ce433f}};
    BigInt<384> op2_c1_bi = {.std_words = {0xb58b9b9, 0x66323bf8, 0xacf6e596, 0xa1379b6f, 0xb797e32f, 0x402aef1f, 0x46d0d44d, 0x2236f552, 0xeb104566, 0x4c8c1800, 0x986c2085, 0x11d6e20e}};
    b.c0.set(op2_c0_bi);
    b.c1.set(op2_c1_bi);
    Fq2 c;
    c.add(a, b);
    Fq2 expected;
    BigInt<384> sum_c0_bi = {.std_words = {0xf6eb0eb9, 0x8e9a7ada, 0x3341eaba, 0xcb207e6b, 0x481d23ff, 0xd70b0c7b, 0x4b6bca2, 0xf4ef57d6, 0xb3d5d090, 0x65309427, 0x553f01d2, 0x14c715d5}};
    BigInt<384> sum_c1_bi = {.std_words = {0xd9079a94, 0xfdb032e7, 0x15468d83, 0x35a2809d, 0x7e0796d5, 0xfe4b2331, 0x34f560fa, 0xd62fa513, 0x46e01984, 0x9ad265eb, 0x5112c8bc, 0x1303f346}};
    expected.c0.set(sum_c0_bi);
    expected.c1.set(sum_c1_bi);
    if (!Fq2::equal(c, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_fq2_sub(void) {
    Fq2 a;
    BigInt<384> op1_c0_bi = {.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}};
    BigInt<384> op1_c1_bi = {.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}};
    a.c0.set(op1_c0_bi);
    a.c1.set(op1_c1_bi);
    Fq2 b;
    BigInt<384> op2_c0_bi = {.std_words = {0x8dc70ef2, 0x619a02d7, 0x119e33e8, 0xb93adfc9, 0x9f0dca12, 0x4bf0b99a, 0x42a6318f, 0x3b88899a, 0xfa82a49d, 0x986a4a62, 0xa26027f5, 0x13ce433f}};
    BigInt<384> op2_c1_bi = {.std_words = {0xb58b9b9, 0x66323bf8, 0xacf6e596, 0xa1379b6f, 0xb797e32f, 0x402aef1f, 0x46d0d44d, 0x2236f552, 0xeb104566, 0x4c8c1800, 0x986c2085, 0x11d6e20e}};
    b.c0.set(op2_c0_bi);
    b.c1.set(op2_c1_bi);
    Fq2 c;
    c.subtract(a, b);
    Fq2 expected;
    BigInt<384> sum_c0_bi = {.std_words = {0xdb5c9b80, 0x8565752b, 0xc15982e9, 0x7756bed7, 0xb285fe, 0xa65a6be7, 0x72ef6c43, 0xe2559026, 0x21c342d, 0x7f77a718, 0x49fe9881, 0x72ba140}};
    BigInt<384> sum_c1_bi = {.std_words = {0xc255d1cd, 0xeb4abaf7, 0x6cacc256, 0x11df49bc, 0x588c69a, 0xe5261793, 0x9ad8cb1f, 0xf63905f3, 0xb40b3b8f, 0x4cd5dd9f, 0x59ba6e4c, 0x9574113}};
    expected.c0.set(sum_c0_bi);
    expected.c1.set(sum_c1_bi);
    if (!Fq2::equal(c, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_fq2_negate(void) {
    Fq2 a;
    BigInt<384> op1_c0_bi = {.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}};
    BigInt<384> op1_c1_bi = {.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}};
    a.c0.set(op1_c0_bi);
    a.c1.set(op1_c1_bi);
    Fq2 c;
    c.negate(a);
    Fq2 expected;
    BigInt<384> sum_c0_bi = {.std_words = {0x96dbaae4, 0x8cfe87fc, 0x8fb0492d, 0xcc6615c, 0x4da19c37, 0xdc167fc0, 0x317487ab, 0xab107d49, 0x89f880e3, 0x7e555df1, 0x86a10cbd, 0x19083f54}};
    BigInt<384> sum_c1_bi = {.std_words = {0x3250c9d0, 0x22810910, 0x49045812, 0x8a411ad1, 0x3041427e, 0xa9109e8f, 0x5608611, 0xb07e9bc4, 0xe77bd8b8, 0xfcd559cb, 0x80d93e62, 0x18d400b2}};
    expected.c0.set(sum_c0_bi);
    expected.c1.set(sum_c1_bi);
    if (!Fq2::equal(c, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_fq2_double(void) {
    Fq2 a;
    BigInt<384> op1_c0_bi = {.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}};
    BigInt<384> op1_c1_bi = {.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}};
    a.c0.set(op1_c0_bi);
    a.c1.set(op1_c1_bi);
    Fq2 c;
    c.multiply2(a);
    Fq2 expected;
    BigInt<384> sum_c0_bi = {.std_words = {0xd247ff8e, 0x5a00f006, 0x43476da4, 0x23cb3d44, 0x521eb3da, 0x1634a5c1, 0x84211627, 0x72cd9c77, 0x72a657e7, 0x998c9389, 0x65bdb3b9, 0x1f1a52b}};
    BigInt<384> sum_c1_bi = {.std_words = {0x9b5dc1b6, 0x2efbeddf, 0xd09f4fdb, 0x28d5ca5a, 0x8cdf674b, 0x7c406823, 0xdc49195b, 0x67f15f81, 0xb79fa83d, 0x9c8c9bd4, 0x714d506e, 0x25a226f}};
    expected.c0.set(sum_c0_bi);
    expected.c1.set(sum_c1_bi);
    if (!Fq2::equal(c, expected)) {
        return "FAIL";
    }

    return "PASS";
}

#define TEST_FQ2_FROBENIUS(name, power, op_c0, op_c1, res_c0, res_c1) \
    do { \
        Fq2 a; \
        BigInt<384> op1_c0_bi = op_c0; \
        BigInt<384> op1_c1_bi = op_c1; \
        a.c0.set(op1_c0_bi); \
        a.c1.set(op1_c1_bi); \
        Fq2 c; \
        c.frobenius_map(a, power); \
        Fq2 expected; \
        BigInt<384> sum_c0_bi = res_c0; \
        BigInt<384> sum_c1_bi = res_c1; \
        expected.c0.set(sum_c0_bi); \
        expected.c1.set(sum_c1_bi); \
        if (!Fq2::equal(c, expected)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fq2_frobenius(void) {
    TEST_FQ2_FROBENIUS("t0", 0,
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}),
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}));

    TEST_FQ2_FROBENIUS("t1", 1,
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}),
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0x3250c9d0, 0x22810910, 0x49045812, 0x8a411ad1, 0x3041427e, 0xa9109e8f, 0x5608611, 0xb07e9bc4, 0xe77bd8b8, 0xfcd559cb, 0x80d93e62, 0x18d400b2}}));

    TEST_FQ2_FROBENIUS("t2", 1,
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0x3250c9d0, 0x22810910, 0x49045812, 0x8a411ad1, 0x3041427e, 0xa9109e8f, 0x5608611, 0xb07e9bc4, 0xe77bd8b8, 0xfcd559cb, 0x80d93e62, 0x18d400b2}}),
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}));

    TEST_FQ2_FROBENIUS("t3", 2,
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}),
                       ARR({.std_words = {0x6923ffc7, 0x2d007803, 0x21a3b6d2, 0x11e59ea2, 0xa90f59ed, 0x8b1a52e0, 0xc2108b13, 0xb966ce3b, 0xb9532bf3, 0xccc649c4, 0xb2ded9dc, 0xf8d295}}),
                       ARR({.std_words = {0xcdaee0db, 0x977df6ef, 0x684fa7ed, 0x946ae52d, 0xc66fb3a5, 0xbe203411, 0xee248cad, 0xb3f8afc0, 0x5bcfd41e, 0x4e464dea, 0xb8a6a837, 0x12d1137}}));
    return "PASS";
}

template <typename Field, const BigInt<384>& characteristic, int maxpower>
const char* test_frobenius_random(void) {
    for (int i = 0; i != few_iters; i++) {
        for (int j = 0; j != maxpower + 1; j++) {
            Field a;
            a.random(random_bytes);
            Field b;
            b.copy(a);

            for (int k = 0; k != j; k++) {
                exponentiate(a, a, characteristic);
            }
            b.frobenius_map(b, j);

            if (!Field::equal(a, b)) {
                return "FAIL";
            }
        }
    }

    return "PASS";
}

#define TEST_FQ2_SQRT(name, op_c0, op_c1, res_c0, res_c1) \
    do { \
        Fq2 a; \
        BigInt<384> op1_c0_bi = op_c0; \
        BigInt<384> op1_c1_bi = op_c1; \
        a.c0.set(op1_c0_bi); \
        a.c1.set(op1_c1_bi); \
        Fq2 c; \
        c.square_root(a); \
        Fq2 expected; \
        BigInt<384> sum_c0_bi = res_c0; \
        BigInt<384> sum_c1_bi = res_c1; \
        expected.c0.set(sum_c0_bi); \
        expected.c1.set(sum_c1_bi); \
        if (!Fq2::equal(c, expected)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
const char* test_fq2_sqrt(void) {
    TEST_FQ2_SQRT("t0",
                  ARR({.std_words = {0x9720e227, 0x476b4c30, 0xfaffdab6, 0x34c2d04, 0xbab51fd9, 0xa57e6fc1, 0x5bf74aa1, 0xdb4a116b, 0x9dfe10e2, 0x1e58b215, 0xf13606ac, 0x7ca7da1}}),
                  ARR({.std_words = {0x7516d2c3, 0xfa8de88b, 0x14f41629, 0x371a75ed, 0x577a3eb6, 0x4cec2dca, 0xa4e99121, 0x212611bc, 0xd77afb3d, 0x8ee5394, 0x650e49d5, 0xec92336}}),
                  ARR({.std_words = {0x704258c5, 0x40b299b2, 0xe8c68b63, 0x6ef7de92, 0x52203e82, 0x6d2ddbe5, 0x3d02c1d3, 0x8d7f1f72, 0xb611c070, 0x881b3e01, 0xbad2ebc5, 0x10f6963b}}),
                  ARR({.std_words = {0xc209e752, 0xc099534f, 0x65676447, 0x76705946, 0xd211efe7, 0x28a20fae, 0xf2afcb1b, 0x6b852aea, 0x105d71a9, 0xa4c93b08, 0x94216330, 0x8d7cfff}}));

    TEST_FQ2_SQRT("t1",
                  ARR({.std_words = {0xd1517a6b, 0xb9f78429, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea}}),
                  BigInt<384>::zero,
                  BigInt<384>::zero,
                  ARR({.std_words = {0xfd4357a3, 0xb9feffff, 0xb153ffff, 0x1eabfffe, 0xf6b0f624, 0x6730d2a0, 0xf38512bf, 0x64774b84, 0x434bacd7, 0x4b1ba7b6, 0x397fe69a, 0x1a0111ea}}));

    return "PASS";
}


const char* test_fq2_legendre(void) {
    if (Fq2::zero.legendre() != 0) {
        return "FAIL (zero)";
    }
    if (Fq2::one.legendre() != 1) {
        return "FAIL (one)";
    }
    if (Fq2::negative_one.legendre() != 1) {
        return "FAIL (negative one)";
    }
    Fq2 x;
    x.multiply_by_nonresidue(Fq2::negative_one);
    if (x.legendre() != -1) {
        return "FAIL (negative one times nonresidue)";
    }

    return "PASS";
}

const char* test_fq2_mul_nonresidue(void) {
    Fq2 nqr = { Fq::one, Fq::one };

    for (int i = 0; i != std_iters; i++) {
        Fq2 a;
        Fq2 b;
        a.random(random_bytes);
        b.copy(a);

        Fq2 tmp1;
        Fq2 tmp2;
        tmp1.multiply_by_nonresidue(a);
        tmp2.multiply(b, nqr);

        if (!Fq2::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq2_pow(void) {
    /* Compare exponentiation with small powers to repeated multiplication. */
    Fq2 a;
    a.random(random_bytes);

    BigInt<384> exponent = BigInt<384>::zero;

    Fq2 tmp1 = Fq2::one;

    for (int i = 0; i != std_iters; i++) {
        Fq2 tmp2;

        exponentiate_restrict(tmp2, a, exponent);

        if (!Fq2::equal(tmp1, tmp2)) {
            return "FAIL (repeated multiplication)";
        }

        tmp1.multiply(tmp1, a);
        exponent.add(exponent, BigInt<384>::one);
    }

    return "PASS";
}

void test_bls12_381_fq2(void) {
    printf("Fq2:\n");
    printf("Squaring...\t\t%s\n", test_fq2_squaring());
    printf("Multiplication...\t%s\n", test_fq2_mul());
    printf("Addition...\t\t%s\n", test_fq2_add());
    printf("Subtraction...\t\t%s\n", test_fq2_sub());
    printf("Negate...\t\t%s\n", test_fq2_negate());
    printf("Double...\t\t%s\n", test_fq2_double());
    printf("Frobenius...\t\t%s\n", test_fq2_frobenius());
    printf("Frobenius (random)...\t%s\n", test_frobenius_random<Fq2, Fq::p_value, 1>());
    printf("Square Root...\t\t%s\n", test_fq2_sqrt());
    printf("Legendre...\t\t%s\n", test_fq2_legendre());
    printf("Multiply Nonresidue...\t%s\n", test_fq2_mul_nonresidue());
    printf("Exponentiate...\t\t%s\n", test_fq2_pow());
    printf("\n");
}

const char* test_fq6_mul_nonresidue(void) {
    Fq6 nqr = { Fq2::zero, Fq2::one, Fq2::zero };

    for (int i = 0; i != std_iters; i++) {
        Fq6 a;
        Fq6 b;
        a.random(random_bytes);
        b.copy(a);

        Fq6 tmp1;
        Fq6 tmp2;
        tmp1.multiply_by_nonresidue(a);
        tmp2.multiply(b, nqr);

        if (!Fq6::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq6_mul_by_c1(void) {
    Fq6 c1_term = { Fq2::zero, Fq2::zero, Fq2::zero };

    for (int i = 0; i != std_iters; i++) {
        Fq2 c1;
        c1.random(random_bytes);
        Fq6 a;
        Fq6 b;
        a.random(random_bytes);
        b.copy(a);

        c1_term.c1.copy(c1);

        Fq6 tmp1;
        Fq6 tmp2;
        tmp1.multiply_by_c1(a, c1);
        tmp2.multiply(b, c1_term);

        if (!Fq6::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq6_mul_by_c01(void) {
    Fq6 c0_c1_term = { Fq2::zero, Fq2::zero, Fq2::zero };

    for (int i = 0; i != std_iters; i++) {
        Fq2 c0;
        c0.random(random_bytes);
        Fq2 c1;
        c1.random(random_bytes);
        Fq6 a;
        Fq6 b;
        a.random(random_bytes);
        b.copy(a);

        c0_c1_term.c0.copy(c0);
        c0_c1_term.c1.copy(c1);

        Fq6 tmp1;
        Fq6 tmp2;
        tmp1.multiply_by_c01(a, c0, c1);
        tmp2.multiply(b, c0_c1_term);

        if (!Fq6::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq6_inverse(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fq6 a;
        a.random(random_bytes);

        Fq6 tmp1;
        Fq6 tmp2;

        tmp2.inverse(a);
        tmp1.multiply(a, tmp2);

        if (!Fq6::equal(tmp1, Fq6::one)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq6_squaring(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fq6 a;
        a.random(random_bytes);

        Fq6 tmp1;
        Fq6 tmp2;

        tmp2.square(a);
        tmp1.multiply(a, a);

        if (!Fq6::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq6_pow(void) {
    /* Compare exponentiation with small powers to repeated multiplication. */
    Fq6 a;
    a.random(random_bytes);

    BigInt<384> exponent = BigInt<384>::zero;

    Fq6 tmp1 = Fq6::one;

    for (int i = 0; i != std_iters; i++) {
        Fq6 tmp2;

        exponentiate(tmp2, a, exponent);

        if (!Fq6::equal(tmp1, tmp2)) {
            return "FAIL (repeated multiplication)";
        }

        tmp1.multiply(tmp1, a);
        exponent.add(exponent, BigInt<384>::one);
    }

    return "PASS";
}

void test_bls12_381_fq6(void) {
    printf("Fq6:\n");
    printf("Multiply Nonresidue...\t%s\n", test_fq6_mul_nonresidue());
    printf("Multiply C1 Term...\t%s\n", test_fq6_mul_by_c1());
    printf("Multiply C01 Terms...\t%s\n", test_fq6_mul_by_c01());
    printf("Inverse...\t\t%s\n", test_fq6_inverse());
    printf("Squaring...\t\t%s\n", test_fq6_squaring());
    printf("Exponentiation...\t%s\n", test_fq6_pow());
    printf("Frobenius (random)...\t%s\n", test_frobenius_random<Fq6, Fq::p_value, 13>());
    printf("\n");
}

const char* test_fq12_mul_by_c014(void) {
    Fq12 term = Fq12::zero;

    for (int i = 0; i != std_iters; i++) {
        Fq2 c0;
        c0.random(random_bytes);
        Fq2 c1;
        c1.random(random_bytes);
        Fq2 c5;
        c5.random(random_bytes);
        Fq12 a;
        Fq12 b;
        a.random(random_bytes);
        b.copy(a);

        term.c0.c0.copy(c0);
        term.c0.c1.copy(c1);
        term.c1.c1.copy(c5);

        Fq12 tmp1;
        Fq12 tmp2;
        tmp1.multiply_by_c014(a, c0, c1, c5);
        tmp2.multiply(b, term);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_inverse(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fq12 a;
        a.random(random_bytes);

        Fq12 tmp1;
        Fq12 tmp2;

        tmp2.inverse(a);
        tmp1.multiply(a, tmp2);

        if (!Fq12::equal(tmp1, Fq12::one)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_squaring(void) {
    /* Ensure that (a * a^{-1}) = 1. */
    for (int i = 0; i != std_iters; i++) {
        Fq12 a;
        a.random(random_bytes);

        Fq12 tmp1;
        Fq12 tmp2;

        tmp2.square(a);
        tmp1.multiply(a, a);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_pow(void) {
    /* Compare exponentiation with small powers to repeated multiplication. */
    Fq12 a;
    a.random(random_bytes);

    BigInt<384> exponent = BigInt<384>::zero;

    Fq12 tmp1 = Fq12::one;

    for (int i = 0; i != std_iters; i++) {
        Fq12 tmp2;

        exponentiate(tmp2, a, exponent);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL (repeated multiplication)";
        }

        tmp1.multiply(tmp1, a);
        exponent.add(exponent, BigInt<384>::one);
    }

    return "PASS";
}

const char* test_fq12_squaring_cyclotomic(void) {
    for (int i = 0; i != std_iters; i++) {
        Fq12 c = generator_pairing;

        Fq12 tmp1;
        Fq12 tmp2;

        tmp2.square_cyclotomic(c);
        tmp1.multiply(c, c);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_pow_cyclotomic(void) {
    BigInt<256> power;
    for (int i = 0; i != std_iters; i++) {
        Fq12 c = generator_pairing;

        Fq12 tmp1;
        Fq12 tmp2;

        power.random(random_bytes);

        tmp2.exponentiate_gt(c, power);
        exponentiate(tmp1, c, power);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_pow_cyclotomic_nodiv(void) {
    BigInt<256> power;
    for (int i = 0; i != std_iters; i++) {
        Fq12 c = generator_pairing;

        Fq12 tmp1;
        Fq12 tmp2;

        power.random(random_bytes);

        tmp2.exponentiate_gt_nodiv(c, power);
        exponentiate(tmp1, c, power);

        if (!Fq12::equal(tmp1, tmp2)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_fq12_gt_random(void) {
    for (int i = 0; i != std_iters; i++) {
        Fq12 a;
        BigInt<256> power;
        a.random_gt(power, generator_pairing, random_bytes);

        Fq12 tmp1;
        exponentiate(tmp1, generator_pairing, power);

        if (!Fq12::equal(tmp1, a)) {
            return "FAIL";
        }
    }

    return "PASS";
}

void test_bls12_381_fq12(void) {
    printf("Fq12:\n");
    printf("Multiply C014 Terms...\t%s\n", test_fq12_mul_by_c014());
    printf("Inverse...\t\t%s\n", test_fq12_inverse());
    printf("Squaring...\t\t%s\n", test_fq12_squaring());
    printf("Exponentiation...\t%s\n", test_fq12_pow());
    printf("Cyclotomic Squaring...\t%s\n", test_fq12_squaring_cyclotomic());
    printf("Cyclotomic Exp...\t%s\n", test_fq12_pow_cyclotomic());
    printf("Cyclotomic Exp (Platforms w/o Division)...\t%s\n", test_fq12_pow_cyclotomic_nodiv());
    printf("GT Random...\t\t%s\n", test_fq12_gt_random());
    printf("Frobenius (random)...\t%s\n", test_frobenius_random<Fq12, Fq::p_value, 13>());
    printf("\n");
}

const char* test_g1_generator(void) {
    Fq x = Fq::zero;
    int i = 0;
    for (;;) {
        /* y^2 = x^3 + b */
        Fq rhs;
        rhs.square(x);
        rhs.multiply(rhs, x);
        rhs.add(rhs, G1Affine::curve_b_value);

        if (rhs.legendre() != -1) {
            Fq y;
            y.square_root(rhs);
            BigInt<Fq::bits_value> yrepr;
            y.get(yrepr);
            Fq negy;
            negy.negate(y);
            BigInt<Fq::bits_value> negyrepr;
            negy.get(negyrepr);

            G1Affine p = {{
                .x = x,
                .y = BigInt<Fq::bits_value>::compare(yrepr, negyrepr) == -1 ? y : negy,
                .infinity = false
            }};
            if (p.is_in_correct_subgroup_assuming_on_curve()) {
                return "FAIL (subgroup)";
            }

            G1 g1;
            g1.multiply(p, G1Affine::cofactor);
            if (!g1.is_zero()) {
                if (i != 4) {
                    return "FAIL (nonzero on wrong iteration)";
                }
                G1Affine g1affine;
                g1affine.from_projective(g1);

                if (!g1affine.is_in_correct_subgroup_assuming_on_curve()) {
                    return "FAIL (affine not in subgroup)";
                }

                if (!G1Affine::equal(g1affine, G1Affine::one)) {
                    return "FAIL (affine not equal to one)";
                }
                break;
            }
        }

        i += 1;
        x.add(x, Fq::one);
    }

    return "PASS";
}

#define TEST_G_VALID(name, g, on_curve, correct_subgroup) \
    do { \
        if (g.is_on_curve() != on_curve) { \
            return "FAIL (" name ": on curve)"; \
        } \
        if (g.is_in_correct_subgroup_assuming_on_curve() != correct_subgroup) { \
            return "FAIL (" name ": correct subgroup)"; \
        } \
    } while (0)
const char* test_g1_valid(void) {
    /* Reject point on isomorphic twist (b = 24) */
    G1Affine t1;
    t1.x.set({.std_words = {0x66c035dc, 0xc58d887b, 0x1d553822, 0x10cbfd30, 0xf1131ee5, 0xaf23e064, 0x4a5d648d, 0x9fe83b1b, 0x508f6a40, 0xf583cc5a, 0xfde0bb13, 0xc3ad2ae}});
    t1.y.set({.std_words = {0x52f03aae, 0x60aa6f95, 0x81300d35, 0xecd01d51, 0xaa8ce167, 0x8af1cdb8, 0x22998c9d, 0xe760f579, 0x795a39e5, 0x953703f5, 0x22df702c, 0xfe3ae09}});
    t1.infinity = false;
    TEST_G_VALID("t1", t1, false, true);

    /* Reject point on a twist. */
    G1Affine t2;
    t2.x.set({.std_words = {0x511e15f5, 0xee6adf83, 0xf27a4ba6, 0x92ddd328, 0xc65adba7, 0xe305bd1a, 0x928b30a8, 0xea034ee2, 0x7c79a7f7, 0xbd8833dc, 0xc0438675, 0xe45c9f0}});
    t2.y.set({.std_words = {0xab7b5dad, 0x3b450eb1, 0x975e8675, 0xa65cb81e, 0xb21726e5, 0xaa548682, 0xa2601d20, 0x753ddf21, 0xbd3ff8b, 0x532d0b64, 0x3f031102, 0x118d2c54}});
    t2.infinity = false;
    TEST_G_VALID("t2", t2, false, false);

    /* Reject point in wrong subgroup. */
    G1Affine t3;
    t3.x.set({.std_words = {0xc6db8fe8, 0x76e1c971, 0xeff2f79, 0xe37e1a61, 0x9f46f0c0, 0x88ae9c49, 0xd6b4e84, 0xf35de9ce, 0x3d1dec54, 0x265bddd2, 0x88458308, 0x12a87780}});
    t3.y.set({.std_words = {0xd526256, 0x8a22defa, 0x56fcb9ae, 0xc57ca554, 0x9bab2610, 0x1ba194e8, 0x9d4f29df, 0x921beef8, 0xad85fa78, 0x5b6fda44, 0xf302cbe0, 0xed74ab9}});
    t3.infinity = false;
    TEST_G_VALID("t3", t3, true, false);

    return "PASS";
}

const char* test_g1_add(void) {
    G1 a;
    a.x.set({.std_words = {0x1d6e8bbf, 0x47fd1f89, 0x8f31a2aa, 0x79a3b044, 0xe5f9968f, 0x81f3339, 0xa5df10d, 0x485e77d5, 0xb55fd479, 0x4c6fcac4, 0x906fb064, 0x86ed4d9}});
    a.y.set({.std_words = {0x61538c65, 0xd25ee64, 0xcd3719b9, 0x9f3bbb2e, 0xe540910d, 0xa06fd3f1, 0x33c35288, 0xcefca683, 0xf8573fa6, 0x570c8005, 0xfe034442, 0x152ca696}});
    a.z.copy(Fq::one);

    G1 b;
    b.x.set({.std_words = {0x96213cbf, 0xeec78f30, 0xea1056e6, 0xa12beb1f, 0x1c40dd54, 0xc286c021, 0xc5e3fb03, 0x5f44314e, 0x37c6e675, 0x24e85387, 0xa594fba8, 0x8abd623}});
    b.y.set({.std_words = {0x88bb7044, 0x6b0528f0, 0x2917ff9e, 0x2fdeb5c8, 0xfac226ad, 0x9a5181f2, 0xf95a872a, 0xd65104c6, 0xa9c61253, 0x1f2998a5, 0x154a9e44, 0xe74846}});
    b.z.copy(Fq::one);

    G1 c;
    c.add(a, b);

    G1Affine d;
    d.from_projective(c);

    G1Affine expected;
    expected.x.set({.std_words = {0xf22235df, 0x6dd3098, 0xc8090260, 0xe865d221, 0xfa50779f, 0xeb96bb99, 0x428e23bb, 0xc4f9a52a, 0xd4f407ef, 0xd178b28d, 0xe9183c69, 0x17fb8905}});
    expected.y.set({.std_words = {0x292b7710, 0xd0de9d65, 0xcf1d9ca7, 0xf6a05f2b, 0x12f20b64, 0x1040e270, 0xb7466c58, 0xeec8d1a5, 0x9dce6376, 0x4bc36264, 0x5455b00a, 0x430cbdc}});
    expected.infinity = false;

    if (!G1Affine::equal(d, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_g1_double(void) {
    G1 a;
    a.x.set({.std_words = {0x1d6e8bbf, 0x47fd1f89, 0x8f31a2aa, 0x79a3b044, 0xe5f9968f, 0x81f3339, 0xa5df10d, 0x485e77d5, 0xb55fd479, 0x4c6fcac4, 0x906fb064, 0x86ed4d9}});
    a.y.set({.std_words = {0x61538c65, 0xd25ee64, 0xcd3719b9, 0x9f3bbb2e, 0xe540910d, 0xa06fd3f1, 0x33c35288, 0xcefca683, 0xf8573fa6, 0x570c8005, 0xfe034442, 0x152ca696}});
    a.z.copy(Fq::one);

    G1 c;
    c.multiply2(a);

    G1Affine d;
    d.from_projective(c);

    G1Affine expected;
    expected.x.set({.std_words = {0xead7018, 0xf939ddfe, 0xe732aecb, 0x3b03942, 0xfdb11851, 0xce0e9c38, 0x687dcde0, 0x4b914c16, 0x77d20533, 0x66c8baf1, 0xf3d83833, 0xaf960cf}});
    expected.y.set({.std_words = {0x5f5177a8, 0x3f067569, 0x178a1ba0, 0x2b6d82ae, 0xd8e51b11, 0x9096380d, 0x60572f4e, 0x1771a65b, 0x13b27555, 0x8b547c13, 0x9a687b1e, 0x13507558}});
    expected.infinity = false;

    if (!G1Affine::equal(d, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_g1_same_y(void) {
    G1Affine a;
    a.x.set({.std_words = {0xc38fc94d, 0xea431f2c, 0x7f5472b, 0x3ad2354a, 0x3f16c26a, 0xfe669f13, 0x21531705, 0x71ffa80, 0x4386d267, 0x7418d48, 0x8ff1fbd6, 0xd5108d}});
    a.y.set({.std_words = {0xe9981766, 0xa776ccbf, 0x4ff40f4a, 0x25563296, 0x50b00499, 0xc09744e6, 0x3e74c8c3, 0x520f7477, 0x982008f0, 0x484c8fc, 0x22008cc6, 0xee2c3d9}});
    a.infinity = false;
    TEST_G_VALID("a", a, true, true);

    G1Affine b;
    b.x.set({.std_words = {0x6b6356b6, 0xe06cdb15, 0x75448ad9, 0xd9040b2d, 0xb0e2aca5, 0xe702f14b, 0xe5f83991, 0xc6e05201, 0x816f207c, 0xf7c75910, 0x78103106, 0x18d4043e}});
    b.y.set({.std_words = {0xe9981766, 0xa776ccbf, 0x4ff40f4a, 0x25563296, 0x50b00499, 0xc09744e6, 0x3e74c8c3, 0x520f7477, 0x982008f0, 0x484c8fc, 0x22008cc6, 0xee2c3d9}});
    b.infinity = false;
    TEST_G_VALID("b", b, true, true);

    G1Affine expected;
    expected.x.set({.std_words = {0xd10c8aa8, 0xef4f05bd, 0x341a2df9, 0xad5bf87, 0x6b78714, 0x81c74242, 0xec39c227, 0x9676ff02, 0x7e55b9f3, 0x4c12c15d, 0x317db9bd, 0x57fd1e}});
    expected.y.set({.std_words = {0x16679345, 0x12883340, 0x615ff0b5, 0xf955cd68, 0xa600f18a, 0xa6998dba, 0xb51049fb, 0x1267d70d, 0xab2ba3e7, 0x4696deb9, 0x177f59d4, 0xb1e4e11}});
    expected.infinity = false;
    TEST_G_VALID("expected", expected, true, true);

    G1 tmp1;
    G1 tmp2;
    tmp1.from_affine(a);
    tmp2.from_affine(b);
    tmp1.add(tmp1, tmp2);

    G1Affine tmp3;
    tmp3.from_projective(tmp1);
    if (!G1Affine::equal(tmp3, expected)) {
        return "FAIL (add projective, compare projective)";
    }
    G1 tmp4;
    tmp4.from_affine(expected);
    if (!G1::equal(tmp1, tmp4)) {
        return "FAIL (add projective, compare affine)";
    }

    G1 tmp5;
    tmp5.from_affine(a);
    tmp5.add(tmp5, b);

    G1Affine tmp6;
    tmp6.from_projective(tmp5);
    if (!G1Affine::equal(tmp6, expected)) {
        return "FAIL (add affine, compare projective)";
    }
    if (!G1::equal(tmp5, tmp4)) {
        return "FAIL (add affine, compare affine)";
    }

    return "PASS";
}

template<typename Result, typename Base>
const char* test_g_mul(void) {
    /* Compare multiplication with small powers to repeated addition. */
    Base a = Base::one;

    BigInt<Fr::bits_value> scalar = BigInt<Fr::bits_value>::zero;

    Result tmp1 = Result::zero;

    for (int i = 0; i != std_iters; i++) {
        Result tmp2;
        tmp2.multiply(a, scalar);

        if (!Result::equal(tmp1, tmp2)) {
            return "FAIL (repeated addition)";
        }

        tmp1.add(tmp1, a);
        scalar.add(scalar, BigInt<Fr::bits_value>::one);
    }

    return "PASS";
}

#define TEST_G_ENCODING(name, g, tmp, encoded) \
    do { \
        encoded.encode(g); \
        if (!encoded.decode(tmp, true)) { \
            return "FAIL (" name "): could not decode"; \
        } \
        if (!Affine::equal(g, tmp)) { \
            return "FAIL (" name ")"; \
        } \
    } while (0)
template <typename Projective, typename Affine, typename Uncompressed, typename Compressed>
const char* test_g_encoding(void) {
    Uncompressed u;
    Compressed c;

    Affine g;
    Affine tmp;

    TEST_G_ENCODING("zero uncompressed", Affine::zero, tmp, u);
    TEST_G_ENCODING("zero compressed", Affine::zero, tmp, c);

    for (int i = 0; i != std_iters; i++) {
        Projective gproj;
        gproj.random_generator(random_bytes);
        g.from_projective(gproj);

        TEST_G_ENCODING("uncompressed", g, tmp, u);
        TEST_G_ENCODING("compressed", g, tmp, c);
    }

    return "PASS";
}

template<typename Result, typename Base, unsigned int window>
const char* test_g_wnaf(void) {
    /* Compare WNAF multiplication with double-add multiplication. */
    Base a;
    BigInt<Fr::bits_value> scalar;

    Result tmp1;
    Result tmp2;

    for (int i = 0; i != std_iters; i++) {
        tmp1.random_generator(random_bytes);
        a.set(tmp1);
        scalar.random(random_bytes);

        tmp1.multiply(a, scalar);
        wnaf_multiply<Result, Base, Fr::bits_value, window>(tmp2, a, scalar);

        if (!Result::equal(tmp1, tmp2)) {
            return "FAIL (double-add)";
        }
    }

    return "PASS";
}


BigInt<256> g1_endomorphism_lambda = {
    .std_words = {0x00000001, 0xfffffffe, 0xfffcb7fc, 0xa7780001, 0x09a1d804, 0x3339d808, 0x299d7d48, 0x73eda753}
};
const char* test_g1_endomorphism_random(void) {
    for (int i = 0; i != std_iters; i++) {
        G1 a;
        a.random_generator(random_bytes);
        G1 b;
        b.copy(a);

        a.multiply(a, g1_endomorphism_lambda);
        b.endomorphism(b);

        if (!G1::equal(a, b)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_g1_multiply_fast(void) {
    G1 a;
    BigInt<Fr::bits_value> scalar;

    G1 tmp1;
    G1 tmp2;

    for (int i = 0; i != std_iters; i++) {
        tmp1.random_generator(random_bytes);
        a.set(tmp1);
        scalar.random(random_bytes);

        tmp1.multiply(a, scalar);
        tmp2.multiply_fast(a, scalar);

        if (!G1::equal(tmp1, tmp2)) {
            return "FAIL (double-add)";
        }
    }

    return "PASS";
}

void test_bls12_381_g1(void) {
    printf("G1:\n");
    printf("Generator...\t\t%s\n", test_g1_generator());
    printf("Valid...\t\t%s\n", test_g1_valid());
    printf("Addition...\t\t%s\n", test_g1_add());
    printf("Doubling...\t\t%s\n", test_g1_double());
    printf("Same Y...\t\t%s\n", test_g1_same_y());
    printf("Multiplication (P)...\t%s\n", test_g_mul<G1, G1>());
    printf("Multiplication (A)...\t%s\n", test_g_mul<G1, G1Affine>());
    printf("w-NAF Mult (P)...\t%s\n", test_g_wnaf<G1, G1, 4>());
    printf("w-NAF Mult (A)...\t%s\n", test_g_wnaf<G1, G1Affine, 4>());
    printf("Endomorphism...\t\t%s\n", test_g1_endomorphism_random());
    printf("Multiplication Fast...\t%s\n", test_g1_multiply_fast());
    printf("Encoding...\t\t%s\n", test_g_encoding<G1, G1Affine, G1Uncompressed, G1Compressed>());
    printf("\n");
}

const char* test_g2_generator(void) {
    Fq2 x = Fq2::zero;
    int i = 0;
    for (;;) {
        /* y^2 = x^3 + b */
        Fq2 rhs;
        rhs.square(x);
        rhs.multiply(rhs, x);
        rhs.add(rhs, G2Affine::curve_b_value);

        if (rhs.legendre() != -1) {
            Fq2 y;
            y.square_root(rhs);
            Fq2 negy;
            negy.negate(y);

            G2Affine p = {{
                .x = x,
                .y = Fq2::compare(y, negy) == -1 ? y : negy,
                .infinity = false
            }};
            if (p.is_in_correct_subgroup_assuming_on_curve()) {
                return "FAIL (subgroup)";
            }

            G2 g2;
            g2.multiply(p, G2Affine::cofactor);
            if (!g2.is_zero()) {
                if (i != 2) {
                    return "FAIL (nonzero on wrong iteration)";
                }
                G2Affine g2affine;
                g2affine.from_projective(g2);

                if (!g2affine.is_in_correct_subgroup_assuming_on_curve()) {
                    return "FAIL (affine not in subgroup)";
                }

                if (!G2Affine::equal(g2affine, G2Affine::one)) {
                    return "FAIL (affine not equal to one)";
                }
                break;
            }
        }

        i += 1;
        x.add(x, Fq2::one);
    }

    return "PASS";
}

const char* test_g2_valid(void) {
    /* Reject point on isomorphic twist (b = 3 * (u + 1)). */
    G2Affine t1;
    t1.x.c0.set({.std_words = {0x9fa35ba9, 0xa757072d, 0x418f6e8a, 0xae3fb2fb, 0x6faa0c7c, 0xc1598ec4, 0x747e3dbe, 0x7a17a004, 0x7c2e5a73, 0xcc65406a, 0x64db4d0c, 0x10b8c03d}});
    t1.x.c1.set({.std_words = {0x2f029778, 0xd30e70fe, 0xf0f5212e, 0xda30772d, 0x9a233a50, 0x5b47a9ff, 0x9b568608, 0xfb777e5b, 0xec71a2b9, 0x789bac1f, 0x2da54405, 0x1342f02e}});
    t1.y.c0.set({.std_words = {0x3de54dca, 0xfe081204, 0x3d47a646, 0xe455171a, 0xc20be98a, 0xa493f36b, 0x410eb608, 0x663015d9, 0xd829a544, 0x78e82a79, 0x45bb3c1e, 0x40a005}});
    t1.y.c1.set({.std_words = {0x48e79377, 0x47098023, 0x204bcfbd, 0xb5ac4dc9, 0xd02f42b2, 0xda361c97, 0xc399e8df, 0x15008b1d, 0x548a3829, 0x68128fd0, 0x5c873aaa, 0x16a613db}});
    t1.infinity = false;
    TEST_G_VALID("t1", t1, false, true);

    /* Reject point on a twist (b = 2 * (u + 1)). */
    G2Affine t2;
    t2.x.c0.set({.std_words = {0xa705f917, 0xf4fdfe95, 0x88233238, 0xc2914df6, 0xca35a34b, 0x37c6b12c, 0xd6c692c, 0x41abba71, 0x62ce8484, 0xffcc4b2b, 0x1b8934ed, 0x6993ec0}});
    t2.x.c1.set({.std_words = {0x5f874e26, 0xb94e92d, 0xbc115d95, 0x44516408, 0x90caa591, 0xe93946b2, 0x131f3555, 0xa5a0c2b7, 0x822367e7, 0x83800965, 0xd8d90bfa, 0x10cf1d3a}});
    t2.y.c0.set({.std_words = {0x79701d97, 0xbf00334c, 0xff204f9a, 0x4fe714f9, 0x2f3d825, 0xab70b280, 0xe73eb51, 0x5a917172, 0xd658adb7, 0x38eb4fd8, 0xbbc1164d, 0xb649051}});
    t2.y.c1.set({.std_words = {0x53d7df75, 0x92258142, 0x3477f887, 0xc196c251, 0x15a804e0, 0xe05e2fbd, 0xad953e04, 0x55f2b8ef, 0xda55265e, 0x7379345e, 0x208fd4cb, 0x377f2e6}});
    t2.infinity = false;
    TEST_G_VALID("t2", t2, false, false);

    /* Reject point in wrong subgroup. */
    G2Affine t3;
    t3.x.c0.set({.std_words = {0x3ea1906c, 0x262cea7, 0x770fabd6, 0x2f08540, 0xa76057be, 0x4ceb92d0, 0xc48c393d, 0x2199bc19, 0x2a6075bf, 0x4a151b73, 0x9108c4a7, 0x17762a3b}});
    t3.x.c1.set({.std_words = {0x44bbd3d1, 0x26f461e9, 0xa9cf6ed6, 0x298f3189, 0xbc2aa150, 0x74328ad8, 0xf9e6e241, 0x7e147f3, 0x83963fff, 0x72a9b635, 0x3c000462, 0x158b008}});
    t3.y.c0.set({.std_words = {0x5ecf103b, 0x91fb0b22, 0x1dc46ba0, 0x55d42edc, 0x997b1943, 0x43939b11, 0x30706b4d, 0x68cad194, 0x924dcea8, 0x3ccfb97b, 0x34588f8d, 0x1660f934}});
    t3.y.c1.set({.std_words = {0xb6dcb9c7, 0xaaed3985, 0xd898d9f4, 0xc1e985d6, 0x3271ac42, 0x618bd2ac, 0xb914b529, 0x3940a2db, 0xcf34f3e7, 0xbeb88137, 0x7c61b694, 0x1699ee57}});
    t3.infinity = false;
    TEST_G_VALID("t3", t3, true, false);

    return "PASS";
}

const char* test_g2_add(void) {
    G2 a;
    a.x.c0.set({.std_words = {0xe303094e, 0x6c994cc1, 0x2c9e85bd, 0xf034642d, 0x352123a9, 0x275094f1, 0x9f3707ac, 0x72556c99, 0x774e9711, 0x4617f2e6, 0xbffe030b, 0x100b2fe5}});
    a.x.c1.set({.std_words = {0x977ec608, 0x7a33555, 0xfe9c0881, 0xe23039d1, 0xaed4fcb5, 0x19ce4678, 0x17667e2e, 0x4637c4f4, 0xe41f6acc, 0x93ebe7c3, 0x9a9a371b, 0xde884f8}});
    a.y.c0.set({.std_words = {0x72e1eb62, 0xe0731194, 0xfe3c9c30, 0x44fb3391, 0x74694006, 0xaa9b066d, 0x4122f231, 0x25fd427b, 0xace35cae, 0xd83112a, 0x407cbb7f, 0x191b2432}});
    a.y.c1.set({.std_words = {0xe97662f5, 0xf68ae82f, 0x68b50b7d, 0xe9860570, 0x11590b48, 0x96c30f04, 0xde569196, 0x9eaa6d19, 0xe2ec2183, 0xf6a03d31, 0x7ca9b39b, 0x3bdafaf}});
    a.z.copy(Fq2::one);

    G2 b;
    b.x.c0.set({.std_words = {0x5910bdd3, 0xa8c763d2, 0xca3add4, 0x408777b3, 0x12e2769e, 0x6115fcc, 0x329ad190, 0x8e73a96b, 0x5ee1f3ab, 0x27c546f7, 0xdd5e7e82, 0xa33d27a}});
    b.x.c1.set({.std_words = {0x54870dfe, 0x93b1ebcd, 0xe1342e11, 0xf1578300, 0xa912407b, 0x8270dca3, 0x62438296, 0x2089faf4, 0xcd48ea66, 0x828e5848, 0x1deb038b, 0x141ecbac}});
    b.y.c0.set({.std_words = {0x57229c3f, 0xf5d2c288, 0x8757ca23, 0x8c157422, 0x75f5dc19, 0xe8d81021, 0xc37cc31d, 0x2767032f, 0x84fd10fe, 0xd5ee2aba, 0x3dd0a4e8, 0x16576ccd}});
    b.y.c1.set({.std_words = {0xa96d1dd2, 0x4da9b6f6, 0x77f1650e, 0x9657f7da, 0xf9ffe6da, 0xbc150712, 0x3f87363a, 0x31898db6, 0xdbd097cc, 0xabab040d, 0x9ba02990, 0x11ad236b}});
    b.z.copy(Fq2::one);

    G2 c;
    c.add(a, b);

    G2Affine d;
    d.from_projective(c);

    G2Affine expected;
    expected.x.c0.set({.std_words = {0x3f2ac8af, 0xcde7ee8a, 0x5975b069, 0xfc642eb3, 0xdd0e64b7, 0xa7de72b7, 0x6eef9cc, 0xf1273e64, 0xff05cb92, 0xababd760, 0x56617e89, 0xd7c204}});
    expected.x.c1.set({.std_words = {0x72cbd2b8, 0xd1a50b85, 0x119d07df, 0x238f0ac6, 0xe5fd6ac2, 0x4dbe924f, 0xc51edf6b, 0x8b203284, 0xbbb21f5e, 0xc8a0b730, 0x29a31274, 0x1a3b59d}});
    expected.y.c0.set({.std_words = {0xa8eaa4c9, 0x9e709e78, 0x3ec342f4, 0xd30921c9, 0x486f5e34, 0x6d1ef332, 0x863633dc, 0x64528ab3, 0x3d7cba97, 0x15938433, 0x1f3cafe8, 0x4cb8474}});
    expected.y.c1.set({.std_words = {0x3640e1a4, 0x242af0dc, 0x65c66919, 0xe90a73ad, 0x4346f9ec, 0x2bd7ca7f, 0xb689644d, 0x38528f92, 0xc59fb21f, 0xb6884dee, 0xec52ba90, 0x3c075d3}});
    expected.infinity = false;

    if (!G2Affine::equal(d, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_g2_double(void) {
    G2 a;
    a.x.c0.set({.std_words = {0xe303094e, 0x6c994cc1, 0x2c9e85bd, 0xf034642d, 0x352123a9, 0x275094f1, 0x9f3707ac, 0x72556c99, 0x774e9711, 0x4617f2e6, 0xbffe030b, 0x100b2fe5}});
    a.x.c1.set({.std_words = {0x977ec608, 0x7a33555, 0xfe9c0881, 0xe23039d1, 0xaed4fcb5, 0x19ce4678, 0x17667e2e, 0x4637c4f4, 0xe41f6acc, 0x93ebe7c3, 0x9a9a371b, 0xde884f8}});
    a.y.c0.set({.std_words = {0x72e1eb62, 0xe0731194, 0xfe3c9c30, 0x44fb3391, 0x74694006, 0xaa9b066d, 0x4122f231, 0x25fd427b, 0xace35cae, 0xd83112a, 0x407cbb7f, 0x191b2432}});
    a.y.c1.set({.std_words = {0xe97662f5, 0xf68ae82f, 0x68b50b7d, 0xe9860570, 0x11590b48, 0x96c30f04, 0xde569196, 0x9eaa6d19, 0xe2ec2183, 0xf6a03d31, 0x7ca9b39b, 0x3bdafaf}});
    a.z.copy(Fq2::one);

    G2 c;
    c.multiply2(a);

    G2Affine d;
    d.from_projective(c);

    G2Affine expected;
    expected.x.c0.set({.std_words = {0x2727c404, 0x91ccb129, 0x2438fad7, 0x91a6cb18, 0x434de902, 0x116aee59, 0x1e52d986, 0xbcedcfce, 0x926e9862, 0x9755d4a3, 0x60fd8024, 0x18bab737}});
    expected.x.c1.set({.std_words = {0x2ae5b99e, 0x4e7c5e0a, 0x7f028961, 0x96e582a2, 0xef2d5926, 0xc74d1cf4, 0x10ef4fe7, 0xeb0cf5e6, 0x8db6e70b, 0x7b4c2bae, 0x3909fca0, 0xf136e4}});
    expected.y.c0.set({.std_words = {0x6ab13e58, 0x954d446, 0x614cf890, 0x3ee42eec, 0x8877577e, 0x853bb1d2, 0x7fde787b, 0xa5a2a51f, 0xc6384188, 0x8b92866b, 0x531d64ef, 0x81a53fe}});
    expected.y.c1.set({.std_words = {0x66239b34, 0x4c5d6076, 0x304d14b3, 0xeddb5f48, 0x6e8e3cb6, 0x337167ee, 0x12ead742, 0xb271f52f, 0x15c83348, 0x244e6c20, 0x6eb9b441, 0x19e2deae}});
    expected.infinity = false;

    if (!G2Affine::equal(d, expected)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_g2_frobenius_random(void) {
    for (int i = 0; i != std_iters; i++) {
        G2 a;
        a.random_generator(random_bytes);
        G2 b;
        b.copy(a);

        a.multiply(a, Fq::p_value);
        b.frobenius_map(b, 1);

        if (!G2::equal(a, b)) {
            return "FAIL";
        }
    }

    return "PASS";
}

const char* test_g2_multiply_div(void) {
    G2 a;
    BigInt<Fr::bits_value> scalar;

    G2 tmp1;
    G2 tmp2;

    for (int i = 0; i != std_iters; i++) {
        tmp1.random_generator(random_bytes);
        a.set(tmp1);
        scalar.random(random_bytes);

        tmp1.multiply(a, scalar);
        tmp2.multiply_div(a, scalar);

        if (!G2::equal(tmp1, tmp2)) {
            return "FAIL (double-add)";
        }
    }

    return "PASS";
}

void test_bls12_381_g2(void) {
    printf("G2:\n");
    printf("Generator...\t\t%s\n", test_g2_generator());
    printf("Valid...\t\t%s\n", test_g2_valid());
    printf("Addition...\t\t%s\n", test_g2_add());
    printf("Doubling...\t\t%s\n", test_g2_double());
    printf("Multiplication (P)...\t%s\n", test_g_mul<G2, G2>());
    printf("Multiplication (A)...\t%s\n", test_g_mul<G2, G2Affine>());
    printf("w-NAF Mult (P)...\t%s\n", test_g_wnaf<G2, G2, 4>());
    printf("w-NAF Mult (A)...\t%s\n", test_g_wnaf<G2, G2Affine, 4>());
    printf("Frobenius (random)...\t%s\n", test_g2_frobenius_random());
    printf("Multiplication Fast...\t%s\n", test_g2_multiply_div());
    printf("Encoding...\t\t%s\n", test_g_encoding<G2, G2Affine, G2Uncompressed, G2Compressed>());
    printf("\n");
}

const char* test_pairing_generator(void) {
    Fq12 c;
    pairing(c, G1Affine::generator, G2Affine::generator);

    if (!Fq12::equal(c, generator_pairing)) {
        return "FAIL";
    }

    return "PASS";
}

const char* test_pairing_zero(void) {
    for (int i = 0; i != std_iters; i++) {
        G1Affine z1 = G1Affine::zero;
        G2Affine z2 = G2Affine::zero;

        G1 a;
        G2 b;
        G1 c;
        G2 d;
        a.random_generator(random_bytes);
        b.random_generator(random_bytes);
        c.random_generator(random_bytes);
        d.random_generator(random_bytes);

        G1Affine a_affine;
        G2Affine b_affine;
        G1Affine c_affine;
        G2Affine d_affine;
        a_affine.from_projective(a);
        b_affine.from_projective(b);
        c_affine.from_projective(c);
        d_affine.from_projective(d);

        Fq12 t1;
        pairing(t1, z1, b_affine);
        if (!Fq12::equal(Fq12::one, t1)) {
            return "FAIL (t1)";
        }

        Fq12 t2;
        pairing(t2, a_affine, z2);
        if (!Fq12::equal(Fq12::one, t2)) {
            return "FAIL (t2)";
        }

        Fq12 t3a;
        AffinePair t3a_pairs[2];
        t3a_pairs[0].g1 = &z1;
        t3a_pairs[0].g2 = &b_affine;
        t3a_pairs[1].g1 = &c_affine;
        t3a_pairs[1].g2 = &d_affine;
        pairing_product(t3a, t3a_pairs, 2, nullptr, 0);

        Fq12 t3b;
        AffinePair t3b_pairs[2];
        t3b_pairs[0].g1 = &a_affine;
        t3b_pairs[0].g2 = &z2;
        t3b_pairs[1].g1 = &c_affine;
        t3b_pairs[1].g2 = &d_affine;
        pairing_product(t3b, t3b_pairs, 2, nullptr, 0);

        if (!Fq12::equal(t3a, t3b)) {
            return "FAIL (t3)";
        }

        Fq12 t4a;
        AffinePair t4a_pairs[2];
        t4a_pairs[0].g1 = &a_affine;
        t4a_pairs[0].g2 = &b_affine;
        t4a_pairs[1].g1 = &z1;
        t4a_pairs[1].g2 = &d_affine;
        pairing_product(t4a, t4a_pairs, 2, nullptr, 0);

        Fq12 t4b;
        AffinePair t4b_pairs[2];
        t4b_pairs[0].g1 = &a_affine;
        t4b_pairs[0].g2 = &b_affine;
        t4b_pairs[1].g1 = &c_affine;
        t4b_pairs[1].g2 = &z2;
        pairing_product(t4b, t4b_pairs, 2, nullptr, 0);

        if (!Fq12::equal(t4a, t4b)) {
            return "FAIL (t4)";
        }
    }

    return "PASS";
}

const char* test_pairing_bilinearity(void) {
    for (int i = 0; i != std_iters; i++) {
        G1 a;
        G2 b;
        a.random_generator(random_bytes);
        b.random_generator(random_bytes);

        G1Affine a_affine;
        G2Affine b_affine;
        a_affine.from_projective(a);
        b_affine.from_projective(b);

        TEST_G_VALID("a", a_affine, true, true);
        TEST_G_VALID("b", b_affine, true, true);

        Fr c;
        Fr d;
        Fr cd;
        c.random(random_bytes);
        d.random(random_bytes);
        cd.multiply(c, d);

        BigInt<Fr::bits_value> cval;
        BigInt<Fr::bits_value> dval;
        BigInt<Fr::bits_value> cdval;
        c.get(cval);
        d.get(dval);
        cd.get(cdval);

        G1 ac;
        G1 ad;
        G2 bc;
        G2 bd;
        ac.multiply(a, cval);
        ad.multiply(a, dval);
        bc.multiply(b, cval);
        bd.multiply(b, dval);

        G1Affine ac_affine;
        G1Affine ad_affine;
        G2Affine bc_affine;
        G2Affine bd_affine;
        ac_affine.from_projective(ac);
        ad_affine.from_projective(ad);
        bc_affine.from_projective(bc);
        bd_affine.from_projective(bd);

        TEST_G_VALID("ac", ac_affine, true, true);
        TEST_G_VALID("ad", ad_affine, true, true);
        TEST_G_VALID("bc", bc_affine, true, true);
        TEST_G_VALID("bd", bd_affine, true, true);

        Fq12 acbd;
        Fq12 adbc;
        Fq12 abcd;
        pairing(acbd, ac_affine, bd_affine);
        pairing(adbc, ad_affine, bc_affine);
        pairing(abcd, a_affine, b_affine);
        exponentiate(abcd, abcd, cdval);

        if (!Fq12::equal(acbd, abcd)) {
            return "FAIL (bilinearity #1)";
        }

        if (!Fq12::equal(adbc, abcd)) {
            return "FAIL (bilinearity #2)";
        }
    }

    return "PASS";
}

const char* test_pairing_miller(void) {
    for (int i = 0; i != std_iters; i++) {
        G1 a;
        G2 b;
        a.random_generator(random_bytes);
        b.random_generator(random_bytes);

        G1Affine a_affine;
        G2Affine b_affine;
        a_affine.from_projective(a);
        b_affine.from_projective(b);

        Fq12 expected;
        pairing(expected, a_affine, b_affine);

        G2Prepared b_prepared;
        b_prepared.prepare(b_affine);

        Fq12 result;
        pairing(result, a_affine, b_prepared);

        if (!Fq12::equal(result, expected)) {
            return "FAIL (prepared vs. affine)";
        }
    }

    for (int i = 0; i != std_iters; i++) {
        G1 a;
        G2 b;
        a.random_generator(random_bytes);
        b.random_generator(random_bytes);

        G1 c;
        G2 d;
        c.random_generator(random_bytes);
        d.random_generator(random_bytes);

        G1Affine a_affine;
        G2Affine b_affine;
        a_affine.from_projective(a);
        b_affine.from_projective(b);

        G1Affine c_affine;
        G2Affine d_affine;
        c_affine.from_projective(c);
        d_affine.from_projective(d);

        Fq12 ab;
        pairing(ab, a_affine, b_affine);

        Fq12 cd;
        pairing(cd, c_affine, d_affine);

        Fq12 abcd;
        abcd.multiply(ab, cd);

        AffinePair pairs[2];
        pairs[0].g1 = &a_affine;
        pairs[0].g2 = &b_affine;
        pairs[1].g1 = &c_affine;
        pairs[1].g2 = &d_affine;

        Fq12 abcd_with_double_loop;
        pairing_product(abcd_with_double_loop, pairs, 2, nullptr, 0);

        if (!Fq12::equal(abcd, abcd_with_double_loop)) {
            return "FAIL (double loop)";
        }
    }

    return "PASS";
}

void test_bls12_381_pairing(void) {
    printf("Pairing:\n");
    printf("Generator...\t\t%s\n", test_pairing_generator());
    printf("Zero...\t\t\t%s\n", test_pairing_zero());
    printf("Bilinearity...\t\t%s\n", test_pairing_bilinearity());
    printf("Miller Loop...\t\t%s\n", test_pairing_miller());
    printf("\n");
}

extern "C" {
    void run_tests(void);
}

void run_tests() {
    test_bls12_381_fr();
    test_bls12_381_fq();
    test_bls12_381_fq2();
    test_bls12_381_fq6();
    test_bls12_381_fq12();
    test_bls12_381_g1();
    test_bls12_381_g2();
    test_bls12_381_pairing();
}
