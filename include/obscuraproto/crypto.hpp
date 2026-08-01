#ifndef OBSCURAPROTO_CRYPTO_HPP
#define OBSCURAPROTO_CRYPTO_HPP

#include <sodium.h>

#include <string>

#include "keys.hpp"
#include "packet.hpp"

namespace ObscuraProto {

    /**
     * @brief Overwrites a byte_vector with zeros using sodium_memzero.
     */
    inline void secure_wipe(byte_vector& v) {
        if (!v.empty()) {
            sodium_memzero(v.data(), v.size());
            v.clear();
        }
    }

    class Crypto {
    public:
        /**
         * @brief Initializes the cryptographic library. Must be called once.
         * @return 0 on success, -1 on error.
         */
        static int init();

        /**
         * @brief Generates a key pair for the key exchange (X25519).
         * @return A KeyPair object.
         */
        static KeyPair generate_kx_keypair();

        /**
         * @brief Generates a key pair for digital signatures (Ed25519).
         * @return A KeyPair object.
         */
        static KeyPair generate_sign_keypair();

        /**
         * @brief Deterministically derives a key pair from a 32-byte seed (Ed25519).
         * @param seed The 32-byte seed.
         * @param len The seed length in bytes (must be exactly 32).
         * @return A KeyPair object.
         * @throws ObscuraProto::InvalidArgument if len is not crypto_sign_SEEDBYTES.
         * @throws ObscuraProto::RuntimeError if seed expansion fails.
         */
        static KeyPair keypair_from_seed(const uint8_t* seed, size_t len);

        /**
         * @brief Derives the Ed25519 public key from a 64-byte private key.
         * @param private_key The 64-byte private key (seed || public).
         * @param len The private key length in bytes (must be exactly 64).
         * @return A PublicKey object.
         * @throws ObscuraProto::InvalidArgument if len is not crypto_sign_SECRETKEYBYTES.
         */
        static PublicKey derive_public_key(const uint8_t* private_key, size_t len);

        /**
         * @brief Creates a digital signature for a given message.
         * @param message The data to sign.
         * @param private_key The signer's private key.
         * @return A Signature object.
         */
        static Signature sign(const byte_vector& message, const PrivateKey& private_key);

        /**
         * @brief Verifies a digital signature.
         * @param signature The signature to verify.
         * @param message The message that was signed.
         * @param public_key The signer's public key.
         * @return True if the signature is valid, false otherwise.
         */
        static bool verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key);

        /**
         * @brief A structure to hold the two derived symmetric keys from ECDH.
         */
        struct SessionKeys {
            byte_vector rx;  // Key for receiving data
            byte_vector tx;  // Key for sending data
        };

        /**
         * @brief [CLIENT] Computes session keys from its own ephemeral keys and the server's ephemeral public key.
         * @param client_kx_kp The client's ephemeral key pair.
         * @param server_eph_pk The server's ephemeral public key.
         * @return The derived session keys.
         */
        static SessionKeys client_compute_session_keys(const KeyPair& client_kx_kp, const PublicKey& server_eph_pk);

        /**
         * @brief [SERVER] Computes session keys from its own ephemeral keys and the client's ephemeral public key.
         * @param server_kx_kp The server's ephemeral key pair.
         * @param client_eph_pk The client's ephemeral public key.
         * @return The derived session keys.
         */
        static SessionKeys server_compute_session_keys(const KeyPair& server_kx_kp, const PublicKey& client_eph_pk);

        /**
         * @brief Encrypts a payload using ChaCha20-Poly1305 IETF variant.
         * @param payload The data to encrypt.
         * @param counter The message counter (used as associated data).
         * @param key The symmetric encryption key.
         * @return An EncryptedPacket in the format [Nonce][Counter][Ciphertext+Tag].
         */
        static EncryptedPacket encrypt(const Payload& payload, uint64_t counter, const byte_vector& key);

        /**
         * @brief A structure to hold the result of a decryption operation.
         */
        struct DecryptedResult {
            Payload payload;
            uint64_t counter;
        };

        /**
         * @brief Decrypts a packet using ChaCha20-Poly1305 IETF variant.
         * @param packet The encrypted packet to decrypt.
         * @param key The symmetric decryption key.
         * @return A DecryptedResult object if decryption is successful.
         * @throws ObscuraProto::RuntimeError if decryption fails.
         */
        static DecryptedResult decrypt(const EncryptedPacket& packet, const byte_vector& key);
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_CRYPTO_HPP
