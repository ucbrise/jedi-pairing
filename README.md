Embedded Pairing Library
========================

#### WARNING: The code in this library is not designed to be side-channel resistant. There is a compile-time flag, `RESIST_SIDE_CHANNELS`, that provides _work-in-progress (not yet complete)_ support for side channel resistance. We advise that you do not depend on our library for side-channel resistance.

This library implements a bilinear group and pairing-based cryptographic schemes, with bindings in Go, C++, and C, suitable for embedded devices. The bilinear group is a re-implementation of https://github.com/zkcrypto/pairing in C++ with C wrappers, as most embedded development is done in C/C++. Furthermore, this library contains assembly optimizations for Cortex-M0+ so that the cryptography is practical on devices running on that hardware. It additionally contains assembly optimizations for x86-64.

Although I originally created this library for the purpose of running pairing-based cryptography on embedded devices, its performance on regular (x86-64-based) machines is comparable to that of state-of-the-art libraries, such as RELIC.

This is not the first high-performance pairing library for embedded-devices, but it has the following advantages:

1. We provide an interface for Go, to support system developers who prefer to code in Go rather than C/C++.

2. The same library runs on both high-performance platforms and embedded-devices. This is crucial for building systems that have components running on both classes of computers. Using two separate libraries, one for high-performance systems and another for embedded systems, is not an option, as ciphertexts and secret keys may not be compatible between the two libraries.

2. Although assembly-optimized for Cortex-M0+ and x86-64, all assembly-optimized routines have a C++ fallback when compiling for platforms without assembly-optimizations. Furthermore, the core library (`src` and `include` directories) do not have any external dependencies other than libc. Use of C++ is primarily for templates, which are used extensively to avoid repeated code; we do not make use of the STL. As a result, our implementation can be run on non-embedded platforms as well, which is necessary for distributed systems work where some, but not all, computers are embedded.

3. Most existing high-performance libraries use Barreto-Naehrig curves, but recently an attack was discovered on those curves, reducing their security level below 128 bits. In contrast, the BLS12-381 curve implemented here is not susceptible to that attack. Thanks to the folks at Zcash for identifying this new curve (see https://z.cash/blog/new-snark-curve/) and for providing an open-source Rust implementation (linked above) under the permissive MIT license.

In the future, I might develop assembly optimizations for other architectures (e.g., ARM64), especially if there is interest. So, please let me know if you are using this library on an architecture for which I have not written assembly optimizations.

Building the Code
-----------------
This code has been tested with g++ version 7 and clang++ version 6 on Ubuntu 16.04/18.04 and on the Atmel SAMR21 SoC. Other compilers/versions may work, but **the compiler must support C++17 features**.

You can compile with either g++ or clang++, but the Makefile defaults to clang++ because, in our experience, clang++ generates faster code than g++ for this library. You can switch compilers by editing the top of the Makefile (just comment out the clang++ section and uncomment the g++ section). You can also compile for Cortex-M0+ this way, by uncommenting the section that uses arm-none-eabi-g++ (we do not support clang++ for embedded builds).

The result of running `make` is the `pairing.a` file, which can be statically linked with your code.

To build the go library, you must first build the `pairing.a` file. To do so, run `make`. This is necessary because CGo will only look for C and C++ files in the same directory as the Go package. Unfortunately, it is not as simple as running `go get`.

Note: When building `pairing.a` using clang++ to use with Go on Ubuntu 18.04 (or, more generally, Ubuntu 16.10 or later), you may need to compile with `-fPIC`. To do this, simply edit the `CXXFLAGS` variable in the Makefile. This is necessary because CGo uses gcc to link, and the build of gcc that ships with Ubuntu 18.04 generates position-independent executables by default, causing linking to fail unless the `pairing.a` file also contains position-independent code (see https://wiki.ubuntu.com/SecurityTeam/PIE). Alternatively, you can download a different build of gcc that does not generate position-code by default, or just use g++ instead of clang++ to build `pairing.a`. You can check your build of gcc by running `gcc -v` and seeing if `--enable-default-pie` is in the output.

License
-------
This code is open-source under the BSD 3-Clause License. Some functions in `src/bls12_381/fq12_cyclotomic.cpp`, which are based on the techniques used by RELIC, are open-source under the Apache 2.0 License.

It should also be noted that most of the implementation of BLS12-381 is based on the one provided in https://github.com/zkcrypto/pairing, which is open-source under the MIT License.
