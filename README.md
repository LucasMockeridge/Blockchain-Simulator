# Blockchain Simulator

An object-oriented proof of work blockchain simulator written in Python.

# Features

* Randomly generates private keys

* Uses elliptic curve cryptography to generate public keys, sign transactions, and verify signatures

* Generates wallet addresses using SHA256 and RIPEMD160

* Complete mining functionality including mining reward transactions

* Verifies transactions by calculating a wallet's balance from the blockchain

* Ensures the previous hash attribute of a new block matched the hash of the last block in the chain for security
