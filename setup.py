import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


setuptools.setup(
    name="HDEd25519",
    version="0.0.2",
    author="Ledger",
    author_email="hello@ledger.com",
    description="HDEd25519 derivation used by Ledger products",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/LedgerHQ/HDEd25519",
    packages=setuptools.find_packages(where=".", exclude=["tests", "tests.*"]),
    package_data={"HDEd25519_nacl": ["py.typed"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "pynacl>=1.4.0",
    ],
)
