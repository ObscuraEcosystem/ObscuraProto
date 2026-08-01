## 1.1.1

### Added
- `Crypto::keypair_from_seed(const uint8_t* seed, size_t len)` — deterministic Ed25519 key pair derivation from a 32-byte seed (`crypto_sign_seed_keypair`). Throws `InvalidArgument` on a wrong seed length and `RuntimeError` if expansion fails.
- `Crypto::derive_public_key(const uint8_t* private_key, size_t len)` — derives the Ed25519 public key from a 64-byte private key (`crypto_sign_ed25519_sk_to_pk`). Throws `InvalidArgument` on a wrong private key length.
- C++ tests for both new APIs (`CryptoTest.KeypairFromSeed`, `CryptoTest.DerivePublicKey`, `CryptoTest.SeedConsistency`).

### Changed
- CMake project version bumped to `1.1.1` (`project(ObscuraProto VERSION 1.1.1)`).

### Fixed
- Rust wrapper `secure_wipe`: removed the intermediate `std::vector` copy of the secret (the wrapper previously copied the buffer via `ObscuraProto::secure_wipe(tmp)` and wiped only the copy, while `rust::Vec` was then zeroed in place with `sodium_memzero`). The buffer is now zeroed in place directly with `sodium_memzero`, then cleared — no duplicate secret material is ever created.
- Rust wrapper: key pair derivation is now fully delegated to the library — `make_keypair_from_sign_key` uses `Crypto::keypair_from_seed` / `Crypto::derive_public_key`. The last direct libsodium call in `wrapper.cpp` is removed. The 32/64-byte contract is preserved; the public Rust API is unchanged.
