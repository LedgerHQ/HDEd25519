from pytest import fixture


@fixture
def mnemonic():
    return "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@fixture
def seed():
    return bytes.fromhex("000102030405060708090a0b0c0d0e0f")
