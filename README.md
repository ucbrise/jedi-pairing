Embedded Pairing Library
========================

#### WARNING: The code in this library is not designed to be side-channel resistant. There is a compile-time flag, `RESIST_SIDE_CHANNELS`, that provides _work-in-progress (not yet complete)_ support for side channel resistance. We advise that you do not depend on our library for side-channel resistance.

This library implements a bilinear group and pairing-based cryptographic schemes for embedded devices. The bilinear group is a re-implementation of https://github.com/zkcrypto/pairing in C++ with C wrappers, as most embedded development is done in C/C++. Furthermore, this library contains assembly optimizations for Cortex-M0+ so that the cryptography is practical on devices running on that hardware. This is not the first library that does this, but it has the following advantages over other libraries:

1. Most existing high-performance libraries use Barreto-Naehrig curves, but recently an attack was discovered on those curves, reducing their security level below 128 bits. In contrast, the BLS12-381 curve implemented here is not susceptible to that attack. Thanks to the folks at Zcash for identifying this new curve (see https://z.cash/blog/new-snark-curve/) and for providing an open-source Rust implementation (linked above) under the permissive MIT license.

2. Although assembly-optimized for Cortex-M0+, all assembly-optimized routines have a C++ fallback when compiling for platforms without assembly-optimizations. Furthermore, the core library (`src` and `include` directories) do not have any external dependencies other than libc. Use of C++ is primarily for templates, which are used extensively to avoid repeated code; we do not make use of the STL. As a result, our implementation can be run on non-embedded platforms as well, which is necessary for distributed systems work where some, but not all, computers are embedded.

3. We provide bindings in Go, to support system developers who prefer to code in Go rather than C/C++.

4. We are working on assembly optimizations for other architectures (e.g., x86-64).

Building the Code
-----------------
This code has been tested with g++ version 7 and clang++ version 6 on Ubuntu 16.04/18.04 and on the Atmel SAMR21 SoC. Other compilers/versions may work, but **the compiler must support C++17 features**.

You can compile with either g++ or clang++, but the Makefile defaults to clang++ because, in our experience, clang++ generates faster code than g++ for this library. You can switch compilers by editing the top of the Makefile (just comment out the clang++ section and uncomment the g++ section). You can also compile for Cortex-M0+ this way, by uncommenting the section that uses arm-none-eabi-g++ (we do not support clang++ for embedded builds).

The result of running `make` is the `pairing.a` file, which can be statically linked with your code.

To build the go library, you must first build the `pairing.a` file, and then copy it into the same directory as the `.go` files. This is necessary because CGo will only look for C and C++ files in the same directory as the Go package. Unfortunately, it is not as simple as running `go get`.

Note: When building `pairing.a` using clang++ to use with Go on Ubuntu 18.04 (or, more generally, Ubuntu 16.10 or later), you may need to compile with `-fPIC`. To do this, simply edit the `CXXFLAGS` variable in the Makefile. This is necessary because CGo uses gcc to link, and the build of gcc that ships with Ubuntu 18.04 generates position-independent executables by default, causing linking to fail unless the `pairing.a` file also contains position-independent code (see https://wiki.ubuntu.com/SecurityTeam/PIE). Alternatively, you can download a different build of gcc that does not generate position-code by default, or just use g++ instead of clang++ to build `pairing.a`. You can check your build of gcc by running `gcc -v` and seeing if `--enable-default-pie` is in the output.

License
-------
This code is open-source under the BSD 3-Clause License.
