# Embedded Cryptography

by [Djones A. Boni](https://github.com/djboni)

* AES
  * AES-ECB
  * AES-CBC
  * AES-Hash
* SHA-1
* SHA-3 / Keccak
  * HASH (SHA-3)
  * XOF (SHAKE)
  * PRNG
  * Authenticated encryption
* Unit-tests with Python

## How to run the tests

To test the C code we use [Unit-Test C with Python](https://github.com/djboni/unit-test-c-with-python).

Clone submodules recursively, enter the tests directory and run start Python 3's unittest module.

```sh
git clone --recurse-submodules https://github.com/djboni/emb-crypto
cd emb-crypto/tests
python3 -m unittest
```

## Licensing

You can use this code both for closed- and open-source projects. You are also free to keep changes to yourself. However we'll enjoy improvements and suggestions.

You are free to copy, modify, and distribute this code with attribution under the terms of the Apache License Version 2.0. See the (doc/LICENSE)[https://raw.githubusercontent.com/djboni/emb-crypto/master/doc/LICENSE] file for details.

