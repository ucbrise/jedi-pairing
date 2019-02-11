#include <stdint.h>
#include <stdio.h>
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

const uint64_t default_duration = 1000000000ull;

void benchmark_time(const char* name, uint64_t (*function)(void), uint64_t duration) {
    printf("%s...\t", name);
    fflush(stdout);
    uint64_t total = 0;
    uint64_t num_samples = 0;
    do {
        uint64_t sample = function();
        if (sample == 0) {
            printf("FAIL\n");
            return;
        }
        total += sample;
        num_samples++;
    } while (total < duration);

    unsigned int micros = (unsigned int) (total / (num_samples * 1000));
    if (micros >= 100) {
        printf("%u us\n", micros);
    } else {
        unsigned int nanos = (unsigned int) (total / num_samples);
        printf("%u ns\n", nanos);
    }
}

Fq ce = Fq::zero;

uint64_t bench_fq_add(void) {
    Fq a;
    a.random(random_bytes);
    ce.random(random_bytes);

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        ce.add(ce, a);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq_subtract(void) {
    Fq a;
    a.random(random_bytes);
    ce.random(random_bytes);

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        ce.subtract(ce, a);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq_multiply2(void) {
    Fq a;
    a.random(random_bytes);
    ce.random(random_bytes);

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        ce.multiply2(a);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq_montgomery(void) {
    Fq a;
    a.random(random_bytes);

    BigInt<384> c;

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        a.get(c);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq_mul(void) {
    Fq a;
    Fq b;
    a.random(random_bytes);
    b.random(random_bytes);

    Fq c;

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        c.multiply(a, b);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq_square(void) {
    Fq a;
    a.random(random_bytes);

    Fq c;

    uint64_t start = current_time_nanos();
    for (int i = 0; i != 1000; i++) {
        c.square(a);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_g1_projective_add(void) {
    G1 a;
    G1 b;
    a.random_generator(random_bytes);
    b.random_generator(random_bytes);

    G1 c;

    uint64_t start = current_time_nanos();
    c.add(a, b);
    uint64_t end = current_time_nanos();
    return end - start;
}

template <unsigned int wnaf_window>
uint64_t bench_g1_projective_scalar_mult(void) {
    G1 a;
    a.random_generator(random_bytes);

    BigInt<256> x;
    x.random(random_bytes);

    uint64_t start = current_time_nanos();
    if constexpr(wnaf_window == 0) {
        a.multiply(a, x);
    } else {
        wnaf_multiply<G1, G1, 256, wnaf_window>(a, a, x);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

template <unsigned int wnaf_window>
uint64_t bench_g1_affine_scalar_mult(void) {
    G1 a;
    a.random_generator(random_bytes);
    G1Affine aff;
    aff.from_projective(a);

    BigInt<256> x;
    x.random(random_bytes);

    uint64_t start = current_time_nanos();
    if constexpr(wnaf_window == 0) {
        a.multiply(aff, x);
    } else {
        wnaf_multiply<G1, G1Affine, 256, wnaf_window>(a, aff, x);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_g1_convert_affine(void) {
    G1 a;
    a.random_generator(random_bytes);

    G1Affine aff;

    uint64_t start = current_time_nanos();
    aff.from_projective(a);
    uint64_t end = current_time_nanos();
    return end - start;
}

template <bool compressed, bool checked>
uint64_t bench_g1_unmarshal(void) {
    G1 a;
    a.random_generator(random_bytes);

    G1Affine aff;
    aff.from_projective(a);

    Encoding<G1Affine, compressed> enc;
    enc.encode(aff);

    uint64_t start = current_time_nanos();
    enc.decode(aff, checked);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_g2_projective_add(void) {
    G2 a;
    G2 b;
    a.random_generator(random_bytes);
    b.random_generator(random_bytes);

    G2 c;

    uint64_t start = current_time_nanos();
    c.add(a, b);
    uint64_t end = current_time_nanos();
    return end - start;
}

template <unsigned int wnaf_window>
uint64_t bench_g2_projective_scalar_mult(void) {
    G2 a;
    a.random_generator(random_bytes);

    BigInt<256> x;
    x.random(random_bytes);

    uint64_t start = current_time_nanos();
    if constexpr(wnaf_window == 0) {
        a.multiply(a, x);
    } else {
        wnaf_multiply<G2, G2, 256, wnaf_window>(a, a, x);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

template <unsigned int wnaf_window>
uint64_t bench_g2_affine_scalar_mult(void) {
    G2 a;
    a.random_generator(random_bytes);
    G2Affine aff;
    aff.from_projective(a);

    BigInt<256> x;
    x.random(random_bytes);

    uint64_t start = current_time_nanos();
    if constexpr(wnaf_window == 0) {
        a.multiply(aff, x);
    } else {
        wnaf_multiply<G2, G2Affine, 256, wnaf_window>(a, aff, x);
    }
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_g2_convert_affine(void) {
    G2 a;
    a.random_generator(random_bytes);

    G2Affine aff;

    uint64_t start = current_time_nanos();
    aff.from_projective(a);
    uint64_t end = current_time_nanos();
    return end - start;
}

template <bool compressed, bool checked>
uint64_t bench_g2_unmarshal(void) {
    G2 a;
    a.random_generator(random_bytes);

    G2Affine aff;
    aff.from_projective(a);

    Encoding<G2Affine, compressed> enc;
    enc.encode(aff);

    uint64_t start = current_time_nanos();
    enc.decode(aff, checked);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq12_mult(void) {
    Fq12 a;
    Fq12 b;
    a.random(random_bytes);
    b.random(random_bytes);

    Fq12 c;

    uint64_t start = current_time_nanos();
    c.multiply(a, b);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq12_exp(void) {
    Fq12 a;
    a.random(random_bytes);

    BigInt<256> x;
    x.random(random_bytes);

    Fq12 c;

    uint64_t start = current_time_nanos();
    exponentiate(c, a, x);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq12_exp_gt_nodiv(void) {
    Fq12 a;
    a.random(random_bytes);

    BigInt<256> x;
    x.random(random_bytes);

    Fq12 c;

    uint64_t start = current_time_nanos();
    c.exponentiate_gt_nodiv(a, x);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq12_exp_gt(void) {
    Fq12 a;
    a.random(random_bytes);

    BigInt<256> x;
    x.random(random_bytes);

    Fq12 c;

    uint64_t start = current_time_nanos();
    c.exponentiate_gt(a, x);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_fq12_random_gt(void) {
    Fq12 a;
    BigInt<256> x;

    Fq12 c;
    c.random(random_bytes);

    uint64_t start = current_time_nanos();
    c.random_gt(x, a, random_bytes);
    uint64_t end = current_time_nanos();
    return end - start;
}

uint64_t bench_pairing(void) {
    G1 a;
    G2 b;
    a.random_generator(random_bytes);
    b.random_generator(random_bytes);

    G1Affine a_aff;
    G2Affine b_aff;
    a_aff.from_projective(a);
    b_aff.from_projective(b);

    Fq12 res;

    uint64_t start = current_time_nanos();
    pairing(res, a_aff, b_aff);
    uint64_t end = current_time_nanos();
    return end - start;
}

extern "C" {
    void run_benchmarks(void);
}

void run_benchmarks(void) {
    benchmark_time("1000 * Fq Addition", bench_fq_add, default_duration);
    benchmark_time("1000 * Fq Subtraction", bench_fq_subtract, default_duration);
    benchmark_time("1000 * Fq Double", bench_fq_multiply2, default_duration);
    benchmark_time("1000 * Fq Montgomery", bench_fq_montgomery, default_duration);
    benchmark_time("1000 * Fq Multiply", bench_fq_mul, default_duration);
    benchmark_time("1000 * Fq Square", bench_fq_square, default_duration);
    printf("\n");
    benchmark_time("G1 Projective Add", bench_g1_projective_add, default_duration / 100);
    benchmark_time("G1 Projective Mult", bench_g1_projective_scalar_mult<0>, default_duration);
    benchmark_time("G1 Affine Mult", bench_g1_affine_scalar_mult<0>, default_duration);
    benchmark_time("G1 Projective w-NAF Mult", bench_g1_projective_scalar_mult<4>, default_duration);
    benchmark_time("G1 Affine w-NAF Mult", bench_g1_affine_scalar_mult<4>, default_duration);
    benchmark_time("G1 Convert to Affine", bench_g1_convert_affine, default_duration / 10);
    benchmark_time("G1 Unmarshal: Compressed, Checked", bench_g1_unmarshal<true, true>, default_duration);
    benchmark_time("G1 Unmarshal: Uncompressed, Checked", bench_g1_unmarshal<false, true>, default_duration);
    benchmark_time("G1 Unmarshal: Compressed, Unchecked", bench_g1_unmarshal<true, false>, default_duration);
    benchmark_time("G1 Unmarshal: Uncompressed, Unchecked", bench_g1_unmarshal<false, false>, default_duration / 1000);
    printf("\n");
    benchmark_time("G2 Projective Add", bench_g2_projective_add, default_duration / 100);
    benchmark_time("G2 Projective Mult", bench_g2_projective_scalar_mult<0>, default_duration);
    benchmark_time("G2 Affine Mult", bench_g2_affine_scalar_mult<0>, default_duration);
    benchmark_time("G2 Projective w-NAF Mult", bench_g2_projective_scalar_mult<4>, default_duration);
    benchmark_time("G2 Affine w-NAF Mult", bench_g2_affine_scalar_mult<4>, default_duration);
    benchmark_time("G2 Convert to Affine", bench_g2_convert_affine, default_duration / 10);
    benchmark_time("G2 Unmarshal: Compressed, Checked", bench_g2_unmarshal<true, true>, default_duration);
    benchmark_time("G2 Unmarshal: Uncompressed, Checked", bench_g2_unmarshal<false, true>, default_duration);
    benchmark_time("G2 Unmarshal: Compressed, Unchecked", bench_g2_unmarshal<true, false>, default_duration);
    benchmark_time("G2 Unmarshal: Uncompressed, Unchecked", bench_g2_unmarshal<false, false>, default_duration / 1000);
    printf("\n");
    benchmark_time("Fq12 Multiply", bench_fq12_mult, default_duration);
    benchmark_time("Fq12 Exponentiate", bench_fq12_exp, default_duration);
    benchmark_time("Fq12 Exponentiate GT", bench_fq12_exp_gt, default_duration);
    benchmark_time("Fq12 Exponentiate GT (Platforms w/o Division)", bench_fq12_exp_gt_nodiv, default_duration);
    benchmark_time("Fq12 Random GT", bench_fq12_random_gt, default_duration);
    benchmark_time("Pairing (Affine)", bench_pairing, default_duration);
}
