# HDEd25519

Hierarchical Deterministic (HD) Ed25519 derivation using pynacl

## Requirements

    python>=3.6
    pynacl>=1.4.0 # For https://github.com/pyca/pynacl/commit/0e2ae90ac8bdc8f3cddf04d58a71da68678e6816

## Usage

```
from HDEd25519_nacl import BIP32Ed25519

mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
((kL, kR), A, c) = BIP32Ed25519.derive_mnemonic("42'/1/2", test_mnemonic)
# (kL, kR) is a private key, A is a public key associated with kL, c is the chaincode
```

## Reference
"BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" paper
from Dmitry Khovratovich and Jason Law
https://github.com/WebOfTrustInfo/rwot3-sf/blob/25271ade6407bee069c9db05d15c209daed3cf81/topics-and-advance-readings/HDKeys-Ed25519.pdf

This file updates https://github.com/LedgerHQ/orakolo/blob/master/src/python/orakolo/HDEd25519.py
with code which is tested, typed and uses robust cryptography.

## Test and Style

This file is formatted using "black --line-length=120"

To view code coverage:

```
pip install coverage
coverage run --source . --module HDEd25519_nacl
coverage report --show-missing
coverage html && open htmlcov/index.html
```
