import pytest

from HDEd25519_nacl import BIP32Ed25519


@pytest.mark.parametrize(
    "path,expected_node",
    [
        (
            "42'/1/2",
            (
                (
                    bytes.fromhex("b02160bb753c495687eb0b0e0628bf637e85fd3aadac109847afa2ad20e69d41"),  # kL
                    bytes.fromhex("00ea111776aabeb85446b186110f8337a758681c96d5d01d5f42d34baf97087b"),  # kR
                ),
                bytes.fromhex("bc738b13faa157ce8f1534ddd9299e458be459f734a5fa17d1f0e73f559a69ee"),  # A
                bytes.fromhex("c52916b7bb856bd1733390301cdc22fd2b0d5e6fab9908d55fd1bed13bccbb36"),  # c
            ),
        ),
        (
            "42'/3'/5",
            (
                (
                    bytes.fromhex("78164270a17f697b57f172a7ac58cfbb95e007fdcd968c8c6a2468841fe69d41"),  # kL
                    bytes.fromhex("15c846a5d003f7017374d12105c25930a2bf8c386b7be3c470d8226f3cad8b6b"),  # kR
                ),
                bytes.fromhex("286b8d4ef3321e78ecd8e2585e45cb3a8c97d3f11f829860ce461df992a7f51c"),  # A
                bytes.fromhex("7e64c416800883256828efc63567d8842eda422c413f5ff191512dfce7790984"),  # c
            ),
        ),
        (
            "42/1",
            (
                (
                    bytes.fromhex("68dccd955fad1603cb9f85c9030246419ee6ae91fb2021b7c81885bb1ee69d41"),  # kL
                    bytes.fromhex("aacb9c2c21da2df4521a88f4f05282b2c30bdf881c0fa85cf73d94adcbe23127"),  # kR
                ),
                bytes.fromhex("08a045fe4fb55ef9aada64f206db8afbc16f04c1eeef4ba9bbb33dd7c1717f8d"),  # A
                bytes.fromhex("ecdee33430eb22253980f96daef7577a4f80549e0ff4c0d9f790bc88675fee0c"),  # c
            ),
        ),
    ],
)
def test_derivation(mnemonic, path, expected_node):
    node = BIP32Ed25519.derive_mnemonic(path, mnemonic)
    assert node == expected_node


def test_public_path(mnemonic):
    ((kL, kR), A, c) = BIP32Ed25519.derive_mnemonic("", mnemonic)
    pub_node = BIP32Ed25519.public_path_key((A, c), "42/1")
    assert pub_node == (
        bytes.fromhex("08a045fe4fb55ef9aada64f206db8afbc16f04c1eeef4ba9bbb33dd7c1717f8d"),  # A
        bytes.fromhex("ecdee33430eb22253980f96daef7577a4f80549e0ff4c0d9f790bc88675fee0c"),  # c
    )


# Use the inputs inspired from
# https://github.com/satoshilabs/slips/blob/8f6a06580870363f60e49f96b568ec4b387c0691/slip-0010.md#test-vector-1-for-ed25519
# The generated keys are different because the derivation algorithm is not SLIP-0010


@pytest.mark.parametrize(
    "path,expected_node",
    [
        (
            "0'",
            (
                (
                    bytes.fromhex("f8c5fe7ef12d7a7f787aa7c3ba107b07f15b9de49528b681f3229f5cb62e725f"),  # kL
                    bytes.fromhex("b74792aee99adb5aeb18e6496d3c8b4d4f84186aacd65d5bd4067c7b39a80fce"),  # kR
                ),
                bytes.fromhex("78701ff87a9da875b1aca15421a7974ab753df5f1dd8abff20aa1cca0eca32ab"),  # A
                bytes.fromhex("bbd2e77e76697e7a062742e8d1018b4981680e1b06a46d110c91719cde1babff"),  # c
            ),
        ),
        (
            "0'/1'",
            (
                (
                    bytes.fromhex("c08190be7808e5a48713eef997775fa5c4ecc8beb3c6ea4c8800ea66b82e725f"),  # kL
                    bytes.fromhex("a0bf04d04f6fe37ea33f5e342a7eba796b878d43f4a60e3d25fd5a044df43cb0"),  # kR
                ),
                bytes.fromhex("a1ab9daf42b069c127c76a9c9ba18351abc6e88b427f988b372db6f63c67bc9f"),  # A
                bytes.fromhex("a6169fe0dec977213da55aa24528371fb5c1c2ba482166a4809b7ec0ef513395"),  # c
            ),
        ),
        (
            "0'/1'/2'",
            (
                (
                    bytes.fromhex("18e0793579b9a9e4bdda1b6080af8afacf4ced61c6da7d2c54d25175bf2e725f"),  # kL
                    bytes.fromhex("5a1a67c65a985fe5a89670369033093e9a5b92108ad8f719190d9f4374b1bf8d"),  # kR
                ),
                bytes.fromhex("8d6929446ef260a556a8a5a4f7f7349611b34b49888abce2a1f2e24634783022"),  # A
                bytes.fromhex("999bb1b7ad36797c7220d16d8932d06ab2b4ed4ba0f0e696cf4d587e64584ffc"),  # c
            ),
        ),
        (
            "0'/1'/2'/2'",
            (
                (
                    bytes.fromhex("e897f708215697cc08c2c22108339545cd39968b1ff71fb2b043b0b4c52e725f"),  # kL
                    bytes.fromhex("fd31b0c0edec775f40084232f2d6cdfd108240deedf0a8ebfca99d1876eb0cf7"),  # kR
                ),
                bytes.fromhex("db3349336ffdaa9c0d26b3917a1112022eb2add24970d127e63ba91ad129835f"),  # A
                bytes.fromhex("902bdf4b257194a212856f212d927659c996efdc27b024def87e955621e2e800"),  # c
            ),
        ),
        (
            "0'/1'/2'/2'/1000000000'",
            (
                (
                    bytes.fromhex("f8598c761ec8fa5ac8f839c10c875d274764bf3060119160c45e5099cb2e725f"),  # kL
                    bytes.fromhex("ee49e9be55323ff980f2e69ed15cf2fd8e18f261221fba4a0c7dc44920066186"),  # kR
                ),
                bytes.fromhex("8ba15e790ecbc5fb70d61440c3b61724e3bcf4fb424f2f97d7f1213eedc28919"),  # A
                bytes.fromhex("371f0cc9a77204eb6237ceadf6196ca2c561cd47c96aeb6c6972d774e7cb8a7e"),  # c
            ),
        ),
        (
            "0'/1'/2'/2'/1000000000'/1",
            (
                (
                    bytes.fromhex("5078beb2de27766359a1324cb1cd8ddf95c33da4bbf00c5f0be8453fcf2e725f"),  # kL
                    bytes.fromhex("1d759c0e151af2b5e7ecf9c5bd9de0bada25b89da2a3cf7814e87728cd138733"),  # kR
                ),
                bytes.fromhex("0c0e552c5248d8314f7ec1629028763229fa81d5513c309976892f237ce2778c"),  # A
                bytes.fromhex("cf5520d54787a8e6b8a0f27c01a9a9f9fbe325c680f675249a548487b9eba6d2"),  # c
            ),
        ),
        (
            "0'/1'/2'/2'/1000000000'/2222",
            (
                (
                    bytes.fromhex("20386f9a0a221493193548b15181197702b5cbcd01ea1aa14cf07e54ce2e725f"),  # kL
                    bytes.fromhex("3571428b848d8c3306d207c2a989ff1bd8ba2c99f8359c0738cb1c488ac69fb8"),  # kR
                ),
                bytes.fromhex("c1b7c7c2fe8e0b50cbdea56fe458ac7a206ab8a72de4275620abe14efe4327a4"),  # A
                bytes.fromhex("f5d9d544726c2b1df82decab71be466e4251c40088bbae394415d8d88150303c"),  # c
            ),
        ),
    ],
)
def test_derive_seed(seed, path, expected_node):
    node = BIP32Ed25519.derive_seed(path, seed)
    assert node == expected_node


def test_public_node():
    base_public_node = (  # 0'/1'/2'/2'/1000000000'
        bytes.fromhex("8ba15e790ecbc5fb70d61440c3b61724e3bcf4fb424f2f97d7f1213eedc28919"),  # A
        bytes.fromhex("371f0cc9a77204eb6237ceadf6196ca2c561cd47c96aeb6c6972d774e7cb8a7e"),  # c
    )
    public_node = BIP32Ed25519.public_child_key(base_public_node, 2222)
    assert public_node == (
        bytes.fromhex("c1b7c7c2fe8e0b50cbdea56fe458ac7a206ab8a72de4275620abe14efe4327a4"),  # A
        bytes.fromhex("f5d9d544726c2b1df82decab71be466e4251c40088bbae394415d8d88150303c"),  # c
    )
