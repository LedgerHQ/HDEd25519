import hashlib
import hmac
import unicodedata
from typing import Tuple

import nacl.bindings

ED25519_N = 2**252 + 27742317777372353535851937790883648493

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
