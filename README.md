High-Performance Pairing Library for both Embedded and Non-Embedded Systems
===========================================================================

#### WARNING: The code in this library is not designed to be side-channel resistant. There is a compile-time flag, `RESIST_SIDE_CHANNELS`, that provides _work-in-progress (not yet complete)_ support for side channel resistance. We advise that you do not depend on our library for side-channel resistance.

This library implements a bilinear group and pairing-based cryptographic schemes, with bindings in Go, C++, and C, suitable for embedded devices. The bilinear group is a re-implementation of https://github.com/zkcrypto/pairing in C++ with C wrappers, as most embedded development is done in C/C++. The C/C++ code implementing the cryptography does not make any system calls, so it is suitable for bare-metal deployment or use with embedded operating systems). Furthermore, this library contains assembly optimizations for Cortex-M0+ (among other platforms) so that the cryptography is practical on devices running on that hardware. You can find more details in our paper describing JEDI, the system we built using this library:

Sam Kumar, Yuncong Hu, Michael P Andersen, Raluca Ada Popa, and David E. Culler. JEDI: Many-to-Many End-to-End Encryption and Key Delegation for IoT. USENIX Security 2019.

Although I originally created this library for the purpose of running pairing-based cryptography on embedded devices, I have since written assembly code to optimize its performance on x86-64 and AArch64 (64-bit ARM) platforms. On my laptop (Intel Core i7-7820HQ), it is the fastest pairing library implementing BLS12-381 (for most operations) that I am aware of (as of December 2018). I have also implemented a wrapper in Go, in order to make the library easier to use on non-embedded systems. The Go wrapper _does_ make system calls to simplify the API, as we do not expect Go to be used for bare-metal or embedded programming.

This is not the first high-performance pairing library for embedded devices, but it has the following advantages:

1. We provide an interface for Go, to support system developers who prefer to code in Go rather than C/C++.

2. The same library runs on both high-performance platforms and embedded-devices. This is crucial for building IoT systems where some, but not all, systems are embedded. Using two separate libraries, one for high-performance platforms and another for embedded platforms, is not an option when building these systems, as ciphertexts and secret keys may not be compatible between the two libraries.

3. Most existing high-performance libraries use Barreto-Naehrig curves, but recently an attack was discovered on those curves, reducing their security level below 128 bits. In contrast, the BLS12-381 curve implemented here is not susceptible to that attack. Thanks to the scientists at Zcash for identifying this new curve (see https://z.cash/blog/new-snark-curve/) and for providing an open-source Rust implementation (linked above) under the permissive MIT license.

4. Although assembly-optimized for Cortex-M0+, x86-64, and AArch64, all assembly-optimized routines have a C++ fallback when compiling for platforms without assembly-optimizations. Furthermore, the core library (`src` and `include` directories) do not have any external dependencies other than libc. Use of C++ is primarily for templates, which are used extensively to avoid repeated code; we do not make use of the STL.

In the future, I might develop assembly optimizations for other architectures (e.g., ARMv7), especially if there is interest. So, please let me know if you are using this library on an architecture for which I have not written assembly optimizations.

Building the Code
-----------------
This code has been tested with g++ version 7 and clang++ version 6 on Ubuntu 16.04/18.04 and on the Atmel SAMR21 SoC. Other compilers/versions may work, but **the compiler must support C++17 features**.

You can compile with either g++ or clang++, but the Makefile defaults to clang++ because, in our experience, clang++ generates faster code than g++ for this library. You can switch compilers by editing the top of the Makefile (just comment out the clang++ section and uncomment the g++ section). You can also compile for Cortex-M0+ this way, by uncommenting the section that uses arm-none-eabi-g++ (we do not support clang++ for embedded builds).

The result of running `make` is the `pairing.a` file, which can be statically linked with your code.

To build the go library, you must first build the `pairing.a` file. To do so, run `make`. This is necessary because CGo will only look for C and C++ files in the same directory as the Go package. Unfortunately, it is not as simple as running `go get`.

Note: When building `pairing.a` using clang++ to use with Go on Ubuntu 18.04 (or, more generally, Ubuntu 16.10 or later), you may need to compile with `-fPIC`. To do this, simply edit the `CXXFLAGS` variable in the Makefile. This is necessary because CGo uses gcc to link, and the build of gcc that ships with Ubuntu 18.04 generates position-independent executables by default, causing linking to fail unless the `pairing.a` file also contains position-independent code (see https://wiki.ubuntu.com/SecurityTeam/PIE). Alternatively, you can download a different build of gcc that does not generate position-independent code by default, or just use g++ instead of clang++ to build `pairing.a`. You can check your build of gcc by running `gcc -v` and seeing if `--enable-default-pie` is in the output. There is code in the Makefile that should do this check automatically.

Using this Library from C++
--------------------------
Using the library in C++ is straightforward. Simply add the `include` directory to your include path with `-I` and statically link your code with the `pairing.a` file obtained by building as above.

Using this Library from C
-------------------------
You can use this library from C in nearly the same way as C++. Header files with the `.h` extension can be safely included into C code (unlike `.hpp` files, which use C++ features). The library can be used by calling functions in the `.h` files, which are wrappers around the C++ functions offering the same functionality.

Using this Library from Go
--------------------------
[![GoDoc](https://godoc.org/github.com/ucbrise/jedi-pairing/lang/go?status.svg)](https://godoc.org/github.com/ucbrise/jedi-pairing/lang/go)

Support for Go is implemented via CGo in multiple packages, according to the functionality that the application needs (raw group elements or cryptographic schemes). These packages are in the `lang/go` directory. You will first need to clone the repository into the appropriate directory in your Go source tree (`src/github.com/samkumar/embedded-pairing`) and then run `make`, as described above, to produce the `pairing.a` file. You can then use the implementation from your code by importing the correct package. For example, to use the BLS12-381 pairing directly, you would use:
```
import "github.com/samkumar/embedded-pairing/lang/go/bls12381"
```

You might also find useful functionality in the `cryptutils` package, which you can import as so:
```
import "github.com/samkumar/embedded-pairing/lang/go/cryptutils"
```

Tests and Benchmarks
--------------------
You can run `make` in the `tests` directory to build a binary called `test`. You can run three commands with this binary:

1. `./test` runs tests for the BLS12-381 implementation, which are mostly taken from the tests used in https://github.com/zkcrypto/pairing.

2. `./test wkdibe` runs tests for the WKD-IBE implementation on top of BLS12-381.

3. `./test bench` runs performance benchmarks.

There are additional tests for the Go interfaces to BLS12-381, WKD-IBE, and IBE. These tests also validate the underlying C/C++ code, because the Go implementations are thin CGo wrappers around the corresponding C/C++ functions. You can run these tests in the standard way for Go, by executing
```
go test
```
in the directly corresponding to the package whose tests you with to run.

Benchmarks are included in these Go tests, which you can run using:
```
go test -bench .
```

For the BLS12-381 benchmarks, I recommend starting with the short version of the benchmarks, which focus on the time-consuming operations. You can run this as follows:
```
go test -bench . -short
```

The other operations, which each take only hundreds of nanoseconds or single-digit microseconds, take much longer to benchmark, as the setup per operation takes much longer than the operation itself. You may wish to run fewer samples for these benchmarks, using the `-benchtime` flag.

Overall, the Go tests may be seen as more comprehensive because they validate correctness at all layers: Go, C, and C++.

License
-------
This code is open-source under the BSD 3-Clause License. Some functions in `src/bls12_381/fq12_cyclotomic.cpp` and `src/bls12_381/curve_fast_multiply.cpp`, which are based on the techniques used by RELIC, are open-source under the Apache 2.0 License.

The logic to implement BLS12-381 using prime-field arithmetic is based on https://github.com/zkcrypto/pairing, which is open-source under the MIT License.
