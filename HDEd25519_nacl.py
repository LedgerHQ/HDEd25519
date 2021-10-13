#!/usr/bin/env python3
"""Hierarchical Deterministic (HD) Ed25519 derivation using pynacl

Requirements:

    python>=3.6
    pynacl>=1.4.0 # For https://github.com/pyca/pynacl/commit/0e2ae90ac8bdc8f3cddf04d58a71da68678e6816

Usage:

    from HDEd25519_nacl import BIP32Ed25519

    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    ((kL, kR), A, c) = BIP32Ed25519.derive_mnemonic("42'/1/2", test_mnemonic)
    # (kL, kR) is a private key, A is a public key associated with kL, c is the chaincode

Reference: "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" paper
from Dmitry Khovratovich and Jason Law
https://github.com/WebOfTrustInfo/rwot3-sf/blob/25271ade6407bee069c9db05d15c209daed3cf81/topics-and-advance-readings/HDKeys-Ed25519.pdf

This file updates https://github.com/LedgerHQ/orakolo/blob/master/src/python/orakolo/HDEd25519.py
with code which is tested, typed and uses robust cryptography.

This file is formatted using "black --line-length=120"

To view code coverage:

    pip install coverage
    coverage run --source . --module HDEd25519_nacl
    coverage report --show-missing
    coverage html && open htmlcov/index.html
"""
import hmac
import hashlib
import unicodedata
from typing import Tuple

import nacl.bindings


ED25519_N = 2 ** 252 + 27742317777372353535851937790883648493

INT256_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


def _NFKDbytes(text: str) -> bytes:
    return unicodedata.normalize("NFKD", text).encode()


def _hmac_sha512(secret: bytes, message: bytes) -> bytes:
    return hmac.new(secret, message, hashlib.sha512).digest()


def _hmac_sha256(secret: bytes, message: bytes) -> bytes:
    return hmac.new(secret, message, hashlib.sha256).digest()


def _scalar_mult_base_ed25519(scalar_32bytes: bytes) -> bytes:
    """Transform a scalar (private key) into an Ed25519 public key"""
    # Reduce the scalar to ensure it is between 0 and the order of the Ed25519 subgroup.
    reduced_scalar: bytes = nacl.bindings.crypto_core_ed25519_scalar_reduce(scalar_32bytes + b"\x00" * 32)
    point: bytes = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(reduced_scalar)
    return point


PrivateNode = Tuple[Tuple[bytes, bytes], bytes, bytes]
PublicNode = Tuple[bytes, bytes]


class BIP32Ed25519:
    """Hierarchical Deterministic (HD) Ed25519 derivation"""

    @staticmethod
    def root_key_slip10(master_secret: bytes) -> PrivateNode:
        """
        INPUT:
          S: 512 bits seed from BIP39/BIP32
          seedkey:"ed25519 seed"

        OUTPUT:
          k = (kL,kR), c

        PROCESS:
          1. compute c = HMAC-SHA256(key=seedkey, Data=0x01 || S)
          2. compute I = HMAC-SHA512(key=seedkey, Data=S)
          3. split I = into tow sequence of 32-bytes sequence kL,Kr
          4. if the third highest bit of the last byte ok kL is not zero:
             S = I
             goto step 1
          5. Set the bits in kL as follows:
               - the lowest 3 bits of the first byte of kL of are cleared
               - the highest bit of the last byte is cleared
               - the second highest bit of the last byte is set
          6. return (kL,kR), c
        """
        key = b"ed25519 seed"
        # root chain code
        c = bytearray(_hmac_sha256(key, b"\x01" + master_secret))
        # KL:KR
        i = bytearray(_hmac_sha512(key, master_secret))
        kL, kR = i[:32], i[32:]
        while (kL[31] & 0b00100000) != 0:
            master_secret = i
            i = bytearray(_hmac_sha512(key, master_secret))
            kL, kR = i[:32], i[32:]
        # the lowest 3 bits of the first byte of kL of are cleared
        kL[0] &= ~0b00000111
        # the highest bit of the last byte is cleared
        kL[31] &= ~0b10000000
        # the second highest bit of the last byte is set
        kL[31] |= 0b01000000

        # root public key
        A = _scalar_mult_base_ed25519(bytes(kL))
        return ((kL, kR), A, c)

    @staticmethod
    def private_child_key(node: PrivateNode, i: int) -> PrivateNode:
        """
        INPUT:
          (kL,kR): 64 bytes private eddsa key
          A      : 32 bytes public key (y coordinate only), optional as A = kR.G (y coordinate only)
          c      : 32 bytes chain code
          i      : child index to compute (hardened if >= 0x80000000)

        OUTPUT:
          (kL_i,kR_i): 64 bytes ith-child private eddsa key
          A_i        : 32 bytes ith-child public key, A_i = kR_i.G (y coordinate only)
          c_i        : 32 bytes ith-child chain code

        PROCESS:
          1. encode i 4-bytes little endian, il = encode_U32LE(i)
          2. if i is less than 2^31
               - compute Z   = HMAC-SHA512(key=c, Data=0x02 | A | il )
               - compute c_  = HMAC-SHA512(key=c, Data=0x03 | A | il )
             else
               - compute Z   = HMAC-SHA512(key=c, Data=0x00 | kL | kR | il )
               - compute c_  = HMAC-SHA512(key=c, Data=0x01 | kL | kR | il )
          3. ci = lowest_32bytes(c_)
          4. set ZL = highest_28bytes(Z)
             set ZR = lowest_32bytes(Z)
          5. compute kL_i:
                zl_  = LEBytes_to_int(ZL)
                kL_  = LEBytes_to_int(kL)
                kLi_ = zl_*8 + kL_
                if kLi_ % order == 0: child does not exist
                kL_i = int_to_LEBytes(kLi_)
          6. compute kR_i
                zr_  = LEBytes_to_int(ZR)
                kR_  = LEBytes_to_int(kR)
                kRi_ = (zr_ + kRn_) % 2^256
                kR_i = int_to_LEBytes(kRi_)
          7. compute A
                A = kLi_.G
          8. return (kL_i,kR_i), A_i, c
        """
        # unpack argument
        ((kLP, kRP), AP, cP) = node
        assert 0 <= i <= 0xFFFFFFFF

        i_bytes = i.to_bytes(4, "little")

        # compute Z,c
        if i < 0x80000000:
            # regular child
            Z = _hmac_sha512(cP, b"\x02" + AP + i_bytes)
            c = _hmac_sha512(cP, b"\x03" + AP + i_bytes)[32:]
        else:
            # hardened child
            Z = _hmac_sha512(cP, b"\x00" + (kLP + kRP) + i_bytes)
            c = _hmac_sha512(cP, b"\x01" + (kLP + kRP) + i_bytes)[32:]
        ZL, ZR = Z[:28], Z[32:]

        # compute KLi
        kLn = int.from_bytes(ZL, "little") * 8 + int.from_bytes(kLP, "little")
        if kLn.bit_length() >= 256:
            # KLn overflowed the capacity for 256-bit integers
            raise ValueError("Unusable path: overflow while computing KLn")
        if kLn % ED25519_N == 0:
            # kLn is 0
            raise ValueError("Unusable path: private key is zero")
        kL = kLn.to_bytes(32, "little")

        # compute KRi
        kRn = (int.from_bytes(ZR, "little") + int.from_bytes(kRP, "little")) & INT256_MASK
        kR = kRn.to_bytes(32, "little")

        # compute Ai
        A = _scalar_mult_base_ed25519(kL)
        return ((kL, kR), A, c)

    @staticmethod
    def public_child_key(node: PublicNode, i: int) -> PublicNode:
        """
        INPUT:
          A      : 32 bytes public key (y coordinate only)
          c      : 32 bytes chain code
          i      : child index to compute (hardened if >= 0x80000000)

        OUTPUT:
          A_i        : 32 bytes ith-child public key, A_i = kR_i.G (y coordinate only)
          c_i        : 32 bytes ith-child chain code

        PROCESS:
          1. encode i 4-bytes little endian, il = encode_U32LE(i)
          2. if i is less than 2^31
               - compute Z   = HMAC-SHA512(key=c, Data=0x02 | A | il )
               - compute c_  = HMAC-SHA512(key=c, Data=0x03 | A | il )
             else
               - reject inputted, hardened path for public path is not possible

          3. ci = lowest_32bytes(c_)
          4. set ZL = highest_28bytes(Z)
          5. compute A_i:
                zl_  = LEBytes_to_int(ZL)
                A_i = (zl_*8).G + A
          6. return A_i, c
        """
        # unpack argument
        (AP, cP) = node
        assert 0 <= i <= 0xFFFFFFFF

        i_bytes = i.to_bytes(4, "little")

        # compute Z,c
        if i < 0x80000000:
            # regular child
            Z = _hmac_sha512(cP, b"\x02" + AP + i_bytes)
            c = _hmac_sha512(cP, b"\x03" + AP + i_bytes)[32:]
        else:
            # hardened child
            raise ValueError("Unexpected hardened child in public key derivation")

        # compute (ZLi*8).G
        ZL = Z[:28]
        ZL_8 = nacl.bindings.crypto_core_ed25519_scalar_mul(ZL + b"\x00\x00\x00\x00", int.to_bytes(8, 32, "little"))
        ZL_8_g = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(ZL_8)

        # compute Ai
        A = nacl.bindings.crypto_core_ed25519_add(ZL_8_g, AP)
        return (A, c)

    @classmethod
    def private_path_key(cls, node: PrivateNode, path: str) -> PrivateNode:
        """
        INPUT:
          (kL,kR): 64 bytes private eddsa key
          A      : 32 bytes public key (y coordinate only), optional as A = kR.G (y coordinate only)
          c      : 32 bytes chain code
          path   : text representation of a derivation path

        OUTPUT:
          (kL_i,kR_i): 64 bytes ith-child private eddsa key
          A_i        : 32 bytes ith-child public key, A_i = kR_i.G (y coordinate only)
          c_i        : 32 bytes ith-child chain code
        """
        for path_part in path.split("/"):
            if path_part.endswith("'"):
                i = int(path_part[:-1]) + 0x80000000
            else:
                i = int(path_part)
            node = cls.private_child_key(node, i)
        return node

    @classmethod
    def public_path_key(cls, node: PublicNode, path: str) -> PublicNode:
        """
        INPUT:
          A      : 32 bytes public key
          c      : 32 bytes chain code
          path   : text representation of a derivation path

        OUTPUT:
          A_i        : 32 bytes ith-child public key
          c_i        : 32 bytes ith-child chain code
        """
        for path_part in path.split("/"):
            if path_part.endswith("'"):
                raise ValueError("Unexpected hardened child in public key derivation")
            else:
                i = int(path_part)
            node = cls.public_child_key(node, i)
        return node

    @staticmethod
    def mnemonic_to_seed(mnemonic: str, passphrase: str = "", prefix: str = "mnemonic") -> bytes:
        """
        INPUT:
           mnemonic: BIP39 words
           passphrase: optional passphrase
           prefix: optional prefix

        OUTPUT:
           512bits seed

        PROCESS:
           1. if passphrase not provided, set passphrase to empty string
           2. if prefix not provided, set prefix to empty string 'mnemonic'
           3. compute seed:
                - compute m_ = NFKD(mnemonic)
                - compute p_ = NFKD(prefix | passphrase)
                - seed = PBKDF_SHA512(password=m_, salt=p_, round=2048)
           4. return 512bits seed
        """
        return hashlib.pbkdf2_hmac("sha512", _NFKDbytes(mnemonic), _NFKDbytes(prefix + passphrase), 2048)

    @classmethod
    def derive_seed(cls, path: str, seed: bytes) -> PrivateNode:
        """
        INPUT:
           path: string path to derive (eg 42'/1/2)
           seed: 512 bits seed (eg: 512bits from BIP39 words)

        OUTPUT
           kL,kR : 64bytes private EDDSA key
           c     : 32 bytes chain code
        """
        node = cls.root_key_slip10(seed)
        if path:
            node = cls.private_path_key(node, path)
        return node

    @classmethod
    def derive_mnemonic(cls, path: str, mnemonic: str, passphrase: str = "", prefix: str = "mnemonic") -> PrivateNode:
        """
        INPUT:
           path: string path to derive (eg 42'/1/2)
           mnemonic: BIP39 words
           passphrase: optional passphrase
           prefix: optional prefix

        OUTPUT
           kL,kR : 64bytes private EDDSA key
           c     : 32 bytes chain code
        """
        seed = cls.mnemonic_to_seed(mnemonic, passphrase, prefix)
        return cls.derive_seed(path, seed)


if __name__ == "__main__":
    test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    node = BIP32Ed25519.derive_mnemonic("42'/1/2", test_mnemonic)
    assert node == (
        (
            bytes.fromhex("b02160bb753c495687eb0b0e0628bf637e85fd3aadac109847afa2ad20e69d41"),  # kL
            bytes.fromhex("00ea111776aabeb85446b186110f8337a758681c96d5d01d5f42d34baf97087b"),  # kR
        ),
        bytes.fromhex("bc738b13faa157ce8f1534ddd9299e458be459f734a5fa17d1f0e73f559a69ee"),  # A
        bytes.fromhex("c52916b7bb856bd1733390301cdc22fd2b0d5e6fab9908d55fd1bed13bccbb36"),  # c
    )

    node = BIP32Ed25519.derive_mnemonic("42'/3'/5", test_mnemonic)
    assert node == (
        (
            bytes.fromhex("78164270a17f697b57f172a7ac58cfbb95e007fdcd968c8c6a2468841fe69d41"),  # kL
            bytes.fromhex("15c846a5d003f7017374d12105c25930a2bf8c386b7be3c470d8226f3cad8b6b"),  # kR
        ),
        bytes.fromhex("286b8d4ef3321e78ecd8e2585e45cb3a8c97d3f11f829860ce461df992a7f51c"),  # A
        bytes.fromhex("7e64c416800883256828efc63567d8842eda422c413f5ff191512dfce7790984"),  # c
    )

    # Test public derivation
    node = BIP32Ed25519.derive_mnemonic("42/1", test_mnemonic)
    assert node == (
        (
            bytes.fromhex("68dccd955fad1603cb9f85c9030246419ee6ae91fb2021b7c81885bb1ee69d41"),  # kL
            bytes.fromhex("aacb9c2c21da2df4521a88f4f05282b2c30bdf881c0fa85cf73d94adcbe23127"),  # kR
        ),
        bytes.fromhex("08a045fe4fb55ef9aada64f206db8afbc16f04c1eeef4ba9bbb33dd7c1717f8d"),  # A
        bytes.fromhex("ecdee33430eb22253980f96daef7577a4f80549e0ff4c0d9f790bc88675fee0c"),  # c
    )

    ((kL, kR), A, c) = BIP32Ed25519.derive_mnemonic("", test_mnemonic)
    pub_node = BIP32Ed25519.public_path_key((A, c), "42/1")
    assert pub_node == (
        bytes.fromhex("08a045fe4fb55ef9aada64f206db8afbc16f04c1eeef4ba9bbb33dd7c1717f8d"),  # A
        bytes.fromhex("ecdee33430eb22253980f96daef7577a4f80549e0ff4c0d9f790bc88675fee0c"),  # c
    )

    # Use the inputs inspired from
    # https://github.com/satoshilabs/slips/blob/8f6a06580870363f60e49f96b568ec4b387c0691/slip-0010.md#test-vector-1-for-ed25519
    # The generated keys are different because the derivation algorithm is not SLIP-0010
    test_seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    node = BIP32Ed25519.derive_seed("0'", test_seed)
    assert node == (
        (
            bytes.fromhex("f8c5fe7ef12d7a7f787aa7c3ba107b07f15b9de49528b681f3229f5cb62e725f"),  # kL
            bytes.fromhex("b74792aee99adb5aeb18e6496d3c8b4d4f84186aacd65d5bd4067c7b39a80fce"),  # kR
        ),
        bytes.fromhex("78701ff87a9da875b1aca15421a7974ab753df5f1dd8abff20aa1cca0eca32ab"),  # A
        bytes.fromhex("bbd2e77e76697e7a062742e8d1018b4981680e1b06a46d110c91719cde1babff"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'", test_seed)
    assert node == (
        (
            bytes.fromhex("c08190be7808e5a48713eef997775fa5c4ecc8beb3c6ea4c8800ea66b82e725f"),  # kL
            bytes.fromhex("a0bf04d04f6fe37ea33f5e342a7eba796b878d43f4a60e3d25fd5a044df43cb0"),  # kR
        ),
        bytes.fromhex("a1ab9daf42b069c127c76a9c9ba18351abc6e88b427f988b372db6f63c67bc9f"),  # A
        bytes.fromhex("a6169fe0dec977213da55aa24528371fb5c1c2ba482166a4809b7ec0ef513395"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'/2'", test_seed)
    assert node == (
        (
            bytes.fromhex("18e0793579b9a9e4bdda1b6080af8afacf4ced61c6da7d2c54d25175bf2e725f"),  # kL
            bytes.fromhex("5a1a67c65a985fe5a89670369033093e9a5b92108ad8f719190d9f4374b1bf8d"),  # kR
        ),
        bytes.fromhex("8d6929446ef260a556a8a5a4f7f7349611b34b49888abce2a1f2e24634783022"),  # A
        bytes.fromhex("999bb1b7ad36797c7220d16d8932d06ab2b4ed4ba0f0e696cf4d587e64584ffc"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'/2'/2'", test_seed)
    assert node == (
        (
            bytes.fromhex("e897f708215697cc08c2c22108339545cd39968b1ff71fb2b043b0b4c52e725f"),  # kL
            bytes.fromhex("fd31b0c0edec775f40084232f2d6cdfd108240deedf0a8ebfca99d1876eb0cf7"),  # kR
        ),
        bytes.fromhex("db3349336ffdaa9c0d26b3917a1112022eb2add24970d127e63ba91ad129835f"),  # A
        bytes.fromhex("902bdf4b257194a212856f212d927659c996efdc27b024def87e955621e2e800"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'/2'/2'/1000000000'", test_seed)
    assert node == (
        (
            bytes.fromhex("f8598c761ec8fa5ac8f839c10c875d274764bf3060119160c45e5099cb2e725f"),  # kL
            bytes.fromhex("ee49e9be55323ff980f2e69ed15cf2fd8e18f261221fba4a0c7dc44920066186"),  # kR
        ),
        bytes.fromhex("8ba15e790ecbc5fb70d61440c3b61724e3bcf4fb424f2f97d7f1213eedc28919"),  # A
        bytes.fromhex("371f0cc9a77204eb6237ceadf6196ca2c561cd47c96aeb6c6972d774e7cb8a7e"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'/2'/2'/1000000000'/1", test_seed)
    assert node == (
        (
            bytes.fromhex("5078beb2de27766359a1324cb1cd8ddf95c33da4bbf00c5f0be8453fcf2e725f"),  # kL
            bytes.fromhex("1d759c0e151af2b5e7ecf9c5bd9de0bada25b89da2a3cf7814e87728cd138733"),  # kR
        ),
        bytes.fromhex("0c0e552c5248d8314f7ec1629028763229fa81d5513c309976892f237ce2778c"),  # A
        bytes.fromhex("cf5520d54787a8e6b8a0f27c01a9a9f9fbe325c680f675249a548487b9eba6d2"),  # c
    )

    node = BIP32Ed25519.derive_seed("0'/1'/2'/2'/1000000000'/2222", test_seed)
    assert node == (
        (
            bytes.fromhex("20386f9a0a221493193548b15181197702b5cbcd01ea1aa14cf07e54ce2e725f"),  # kL
            bytes.fromhex("3571428b848d8c3306d207c2a989ff1bd8ba2c99f8359c0738cb1c488ac69fb8"),  # kR
        ),
        bytes.fromhex("c1b7c7c2fe8e0b50cbdea56fe458ac7a206ab8a72de4275620abe14efe4327a4"),  # A
        bytes.fromhex("f5d9d544726c2b1df82decab71be466e4251c40088bbae394415d8d88150303c"),  # c
    )

    base_public_node = (  # 0'/1'/2'/2'/1000000000'
        bytes.fromhex("8ba15e790ecbc5fb70d61440c3b61724e3bcf4fb424f2f97d7f1213eedc28919"),  # A
        bytes.fromhex("371f0cc9a77204eb6237ceadf6196ca2c561cd47c96aeb6c6972d774e7cb8a7e"),  # c
    )
    public_node = BIP32Ed25519.public_child_key(base_public_node, 2222)
    assert public_node == (
        bytes.fromhex("c1b7c7c2fe8e0b50cbdea56fe458ac7a206ab8a72de4275620abe14efe4327a4"),  # A
        bytes.fromhex("f5d9d544726c2b1df82decab71be466e4251c40088bbae394415d8d88150303c"),  # c
    )
