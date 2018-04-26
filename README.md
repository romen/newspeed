# `newspeed` - A newer OpenSSL `speed`

This is a WIP project reimplementing `openssl speed` to use modern
APIs (e.g. `EVP_PKEY`).

## Table of Contents

<!-- toc -->

- [Design](#design)
- [Caveats](#caveats)
- [Prerequisites](#prerequisites)
  * [Perf](#perf)
- [Build](#build)
  * [Build-time configuration](#build-time-configuration)
    + [Number of runs for each operation](#number-of-runs-for-each-operation)
    + [Alternative sampling providers](#alternative-sampling-providers)
  * [Build instructions](#build-instructions)
- [Usage](#usage)
  * [Notes](#notes)
  * [Examples](#examples)
    + [Benchmark X25519](#benchmark-x25519)
    + [Benchmark ED25519](#benchmark-ed25519)
    + [Benchmark NIST-P256 EC](#benchmark-nist-p256-ec)
    + [Benchmark RSA keygen](#benchmark-rsa-keygen)
    + [Benchmark DSA sign](#benchmark-dsa-sign)
    + [Benchmark several different operations at once](#benchmark-several-different-operations-at-once)
- [JSON Output](#json-output)
- [Other links](#other-links)

<!-- tocstop -->

## Design

`newspeed` runs a specified set of operations a number of times in a
loop and records the number of elapsed CPU cycles.

The main loop can be described through the following pseudocode:

```python
main_benchmarking_loop(operation)
  for o in operation.out_count
    for i in operation.in_count
      operation.pre_hook()

      SAMPLING_START()
      for x in iterations_per_sample
        operation.run()
      SAMPLING_END()

      sample = SAMPLING_DELTA / iterations_per_sample

      operation.post_hook()
```

The reason why we have two nested loops (`out_count` and `in_count`) is
to abide to the recommendations for some of the alternative sampling
providers.

To improve the statistical quality of each sample, we further average
the measured elapsed CPU cycles over a number of iterations per sample
in the innermost loop.

The total number of runs for each operation is thus equal to

```python
operation.out_count * operation.in_count * iterations_per_sample
```

Even tough it is possible to redefine the number of iterations in
out_count and in_count for each defined operation, currently all
operation definitions default to use
[global parameters set at compile time][self:build-time-configuration]
to define these values.

When `out_count > 1` (which is not the default), part of the code in
`newspeed` will attempt a statistical comparison of the sampled values,
according to the guidelines described in the
[whitepaper][intel_benchmark_whitepaper]
which inspired one of the alternative sampling providers.

## Caveats

*   The list of operations supported is currently limited to
    -   `EVP_PKEY` keygen
    -   `EVP_PKEY` key derivation (e.g. DH, ECDH)
    -   `EVP_PKEY` sign/verify
    -   `EVP_DigestSign`/`EVP_DigestVerify`
*   The number of iterations per operations is
    [fixed at build time][self:build-time-configuration]
*   The current code would benefit a lot from refactoring and
    restructuring, especially to make it easier to add support for new
    operations and to maintain existing ones
*   The output on the TTY is cryptic and hard to use, and improving it
    is part of future plans for the tool (the
    [JSON output][self:json-output] is what should be used for statistics)

## Prerequisites

### Perf

The default method for measuring elapsed cycles in `newspeed` is based
on the Linux `perf` tool, as it has the benefit of being portable to
any platform we were interested in.

On Ubuntu/Debian:

```bash
apt-get install linux-tools-common linux-tools-generic \
  linux-tools-$(uname -r)
```

This is a requiremnt at build time, unless a different sampling
provider is selected (alternatives can be selected through
[preprocessors defines][self:build-time-configuration], but they underwent
less testing).

Also, as a run-time requirement, depending on the security environment,
using `perf` as an unprivileged user might require adding
`CAP_SYS_ADMIN` capability or allowing unprivileged access to `perf`
event counters:

```bash
echo 1 | sudo tee /proc/sys/kernel/perf_event_paranoid
```

## Build

### Build-time configuration

`src/newspeed_config.h` includes defines affecting the core
functionality of `newspeed`.

#### Number of runs for each operation

Currently the number of runs for each operation is statically
determined at compile time as illustrated in the
[Design section][self:design], and the total number of runs for each
operation is equal to:

```python
operation.out_count * operation.in_count * iterations_per_sample
```

*   `iterations_per_sample` depends on

    ```c
    #define HYPERLOOP 7
    ```

    ```python
    iterations_per_sample = 2**HYPERLOOP # 2 to the power of HYPERLOOP
    ```
*   `operation.in_count` defaults to

    ```c
    #define OP_DEFAULT_IN_COUNT 100
    ```

    for each defined operation;
*   `operation.out_count` defaults to

    ```c
    #define OP_DEFAULT_OUT_COUNT 1
    ```

    for each defined operation; if greater than 1, part of the code in
    `newspeed` will attempt a statistical comparison of the sampled
    values, according to the guidelines described in the
    [whitepaper][intel_benchmark_whitepaper] which inspired one of the
    alternative sampling providers.


#### Alternative sampling providers

```c
#define SAMPLING_INTEL_WHITEPAPER 1
#define SAMPLING_SUPERCOP 2
#define SAMPLING_MODIFIED_SUPERCOP 3
#define SAMPLING_PERF 4

#define SAMPLING SAMPLING_PERF
```

The `SAMPLING` declaration selects one of the implemented sampling
providers.
The default is `SAMPLING_PERF` as it is portable and more reliable on
the environments we targeted, with the caveat that it adds some
build-time and run-time [requirements][self:perf].

The other providers are currently `x86` only, and may also require
tweaking the number of runs per operation to increase the reliability of
the measurements.

### Build instructions

```bash
export OPENSSL_PREFIX=/opt/openssl-master
TMP_BUILD_DIR=./build
rm -rf ${TMP_BUILD_DIR}; mkdir -p ${TMP_BUILD_DIR}
cd ${TMP_BUILD_DIR}
cmake -DCMAKE_BUILD_TYPE=Debug \
	-DOPENSSL_ROOT_DIR=${OPENSSL_PREFIX} \
	-DCMAKE_INSTALL_PREFIX:PATH=${OPENSSL_PREFIX} \
	${CMAKE_EXTRA_OPTS} ..
make ${MAKE_OPTS}

# Optionally install newspeed to ${OPENSSL_PREFIX}/bin/
sudo make install
```

## Usage

```bash
$OPENSSL_PREFIX/bin/newspeed
Usage: newspeed [options]
Valid options are:
 -help                  Display this summary
 -engine val            Use engine, possibly a hardware device
 -evp_pkey_keygen val   Benchmark EVP_PKEY key-pair generation
 -evp_pkey_derive val   Benchmark EVP_PKEY derive (DH) operation
 -evp_pkey_dss val      Benchmark EVP_PKEY digital signature scheme (sign+verify)
 -evp_pkey_sign val     Benchmark EVP_PKEY (DSS) sign operation
 -evp_pkey_verify val   Benchmark EVP_PKEY (DSS) verify operation
 -evp_digest_dss val    Benchmark EVP_DigestSign/DigestVerify digital signature scheme
 -evp_digestsign val    Benchmark EVP_DigestSign operation
 -evp_digestverify val  Benchmark EVP_DigestVerify operation
 -json outfile          Output json stats to file
 -noop                  Benchmark noop operation
```

All the `-evp_*` options take as argument the name of the algorithm on
which to operate, with the following syntax:
*   `EVP_PKEY_EC:<curve_name>` performs the operation on the elliptic
    curve identified by the specified `<curve_name>`.
    *For a list of valid curve names:*
    ```bash
    $OPENSSL_PREFIX/bin/openssl ecparam -list_curves
    ```
*   `EVP_PKEY_RSA:<bits>` performs the operation using an RSA key with
    the specified bit length.
*   `EVP_PKEY_DSA:<bits>` performs the operation using a DSA key with
    the specified bit length.
*   Any other argument is directly fed through OpenSSL methods to
    retrieve a corresponding `EVP_PKEY` implementation.

Most of the time `-evp_digest*` and the corresponding
`-evp_pkey_{sign|derive|dss}` are interchangeable, as the
`EVP_DigestSign` API wraps around the `EVP_PKEY` API.
The notable exception is for `ED25519` signatures, which in OpenSSL
1.1.1 are implemented directly through the `EVP_DigestSign` API and do
not support `EVP_PKEY_sign`.

**NOTE**: An `ENGINE` might expose a cryptosystem through different APIs
than upstream OpenSSL: e.g. with [libsuola][libsuola], `ED25519` is
accessible through both the `EVP_DigestSign` API and the `EVP_PKEY_sign`
API.

### Notes

*   **NOTE**: Don't load more than one engine for benchmarking!
*   **NOTE**: `-engine` is optional, but should be the first
    option when loading an `ENGINE`!

*Both recommendations are not strictly enforced, as for debugging and
development it might be useful to load more engines and in different
orders.*

### Examples

#### Benchmark X25519

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -engine libsuola-hacl \
  -evp_pkey_keygen X25519 \
  -evp_pkey_derive X25519 \
  -json results.json
```

#### Benchmark ED25519

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -engine libsuola-sodium \
  -evp_pkey_keygen ED25519 \
  -evp_digest_dss ED25519 \
  -json results.json
```

#### Benchmark NIST-P256 EC

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -evp_pkey_keygen EVP_PKEY_EC:prime256v1 \
  -evp_pkey_derive EVP_PKEY_EC:prime256v1 \
  -evp_digest_dss EVP_PKEY_EC:prime256v1 \
  -json results.json
```

#### Benchmark RSA keygen

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -evp_pkey_keygen EVP_PKEY_RSA:2048 \
  -json results.json
```

#### Benchmark DSA sign

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -evp_pkey_sign EVP_PKEY_DSA:1024 \
  -json results.json
```

#### Benchmark several different operations at once

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -engine libsuola-hacl \
  -evp_pkey_keygen EVP_PKEY_EC:prime256v1 \
  -evp_pkey_keygen X25519 \
  -evp_pkey_keygen ED25519 \
  -evp_pkey_derive EVP_PKEY_EC:prime256v1 \
  -evp_pkey_derive X25519 \
  -evp_digest_dss EVP_PKEY_EC:prime256v1 \
  -evp_digest_dss ED25519 \
  -json results.json
```

```bash
$OPENSSL_PREFIX/bin/newspeed \
  -engine libsuola-hacl \
  -evp_pkey_keygen EVP_PKEY_RSA:1024 \
  -evp_pkey_derive X25519 \
  -evp_pkey_sign ED25519 \
  -evp_digest_dss EVP_PKEY_DSA:1024 \
  -evp_pkey_dss EVP_PKEY_EC:prime256v1 \
  -json results.json
```

## JSON Output

The preferred output format for `newspeed` benchmarks is JSON and this
sections aims at briefly describing the adopted schema.

A `newspeed` JSON results file contains only one object, describing
metadata related to the execution of `newspeed` (i.e. pid, hostname,
date, openssl version, command line arguments, loaded engine).

The `operations` member contains an array of objects describing each
operation benchmarked by the `newspeed` execution: each `operation`
object has metadata describing the algorithm name, operation name, and
the `out_count`, `in_count` and `iterations_per_sample` parameters
previously explained.

The `RUNS` member of a `operation` object contains an array (of length
`out_count`) of objects composed by a numerical index `j` (i.e.
`0 < j < out_count`) and a `values` array containing `in_count` CPU
cycles samples (each averaged over `iterations_per_sample` operation
runs).

```json
{
  "pid": 24913,
  "machine": "picchiopanciagialla",
  "engine": "libsuola-sodium",
  "date": "2018-04-26 20:18:30 +0000",
  "openssl_v": "0x10101003",
  "openssl_v_txt": "OpenSSL 1.1.1-pre3 (beta) 20 Mar 2018",
  "argv": [
    "/opt/openssl-111-pre3/bin/newspeed",
    "-engine",
    "libsuola-sodium",
    "-evp_pkey_derive",
    "X25519",
    "-evp_pkey_sign",
    "ED25519",
    "-json",
    "test.json"
  ],
  "operations": [
    {
      "bits": 253,
      "alg_name": "X25519",
      "op_name": "evp_pkey_derive",
      "op_id": "0x17f99b0",
      "out_count": 1,
      "in_count": 10,
      "iterations_per_sample": 128,
      "RUNS": [
        {
          "j": 0,
          "values": [
            136739,
            142329,
            135723,
            137869,
            141245,
            135261,
            136663,
            135096,
            135370,
            135009
          ]
        }
      ]
    },
    {
      "bits": 253,
      "alg_name": "ED25519",
      "op_name": "evp_pkey_sign",
      "op_id": "0x1800860",
      "out_count": 1,
      "in_count": 10,
      "iterations_per_sample": 128,
      "RUNS": [
        {
          "j": 0,
          "values": [
            83261,
            84846,
            89588,
            90641,
            83401,
            85825,
            93010,
            88041,
            83294,
            83383
          ]
        }
      ]
    }
  ]
}
```

## Other links

*   [libsuola][libsuola]
*   [How to Benchmark Code Execution Times on Intel® IA-32 and IA-64 Instruction Set Architectures][intel_benchmark_whitepaper]

<!-- autoref links -->

[self:build-time-configuration]: #build-time-configuration
[self:design]: #design
[self:perf]: #perf
[self:json-output]: #json-output

<!-- links -->

[libsuola]: https://github.com/romen/libsuola
[intel_benchmark_whitepaper]: https://www.intel.de/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
