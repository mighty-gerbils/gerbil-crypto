# Gerbil-Crypto

Gerbil-crypto is collection of cryptographic primitives that complement
those included in Gerbil itself (as interfaced from OpenSSL).

Current primitives are sufficient to interface with Ethereum: keccak256 and secp256k1.

More primitives may be added in the future.

## Copyright and License

Copyright 2020 Mutual Knowledge Systems, Inc. All rights reserved.
Gerbil-crypto is distributed under the Apache License, version 2.0. See the file [LICENSE](LICENSE).

## Installation instructions

### Dependencies

You need to first install the [Gerbil Scheme](https://cons.io) compiler.
Gerbil depends on `openssl` so you'll have it installed.

Then you must install the [Gerbil Clan](https://github.com/fare/gerbil-utils) utilities
and the [Gerbil-POO](https://github.com/fare/gerbil-poo) object system,
which `gxpkg` may automatically download for you.

Finally, you need to install the following libraries:
- `libsecp256k1`: On Debian/Ubuntu, install with `apt install libsecp256k1-dev`
- `libsodium`: On Debian/Ubuntu, install with `apt install libsodium-dev`

The nix recipe for `gerbil-crypto` installs these dependencies automatically.
YMMV on other Linux distributions.

Also, you need to install the `blst` library.
```
# Clone the repository  
git clone https://github.com/supranational/blst.git

# Build the library
cd blst && ./build.sh

# Copy the library and headers
sudo cp libblst.a /usr/local/lib/ && sudo cp bindings/blst.h bindings/blst_aux.h /usr/local/include/

# Clean up
cd .. && rm -rf blst
```

### Building

Once all dependencies are installed, you may build with:

    ./build.ss

Test with:

    ./unit-tests.ss
