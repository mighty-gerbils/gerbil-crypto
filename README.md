# Gerbil-Crypto

Gerbil-crypto is collection of cryptographic primitives that complement
those included in Gerbil itself (as interfaced from OpenSSL).

Current primitives are sufficient to interface with Ethereum: keccak256 and secp256k1.

More primitives may be added in the future.

### Copyright and License

Copyright 2020 Mutual Knowledge Systems, Inc. All rights reserved.
Gerbil-crypto is distributed under the Apache License, version 2.0. See the file [LICENSE](LICENSE).

### Installation instructions

You need to first install [Gerbil](https://cons.io) and
the [Gerbil Clan](https://github.com/fare/gerbil-utils) utilities.

Build with:

    ./build.ss

Test with:

    ./unit-tests.ss
