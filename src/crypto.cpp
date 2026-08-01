#include "obscuraproto/crypto.hpp"

#include <sodium.h>

#include <atomic>

#include "obscuraproto/errors.hpp"

// Helper for 64-bit network byte order conversion
#if defined(_WIN32) || (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
static uint64_t htonll_local(uint64_t val) {
    return (((uint64_t) htonl(val)) << 32) + htonl(val >> 32);
}
static uint64_t ntohll_local(uint64_t val) {
    return (((uint64_t) ntohl(val)) << 32) + ntohl(val >> 32);
}
#else
#define htonll_local(x) (x)
#define ntohll_local(x) (x)
#endif

namespace ObscuraProto {

    static std::atomic<bool> g_sodium_initialized = false;

    int Crypto::init() {
        if (g_sodium_initialized) {
            return 0;  // Already successfully initialized
        }

        if (sodium_init() < 0) {
            return -1;  // Initialization failed
        }

        g_sodium_initialized = true;
        return 0;
    }

    KeyPair Crypto::generate_kx_keypair() {
        KeyPair kp;
        kp.publicKey.data.resize(crypto_kx_PUBLICKEYBYTES);
        kp.privateKey.data.resize(crypto_kx_SECRETKEYBYTES);
        crypto_kx_keypair(kp.publicKey.data.data(), kp.privateKey.data.data());
        return kp;
    }

    KeyPair Crypto::generate_sign_keypair() {
        KeyPair kp;
        kp.publicKey.data.resize(crypto_sign_PUBLICKEYBYTES);
        kp.privateKey.data.resize(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(kp.publicKey.data.data(), kp.privateKey.data.data());
        return kp;
    }

    KeyPair Crypto::keypair_from_seed(const uint8_t* seed, size_t len) {
        if (len != crypto_sign_SEEDBYTES) {
            throw InvalidArgument("Seed must be exactly 32 bytes.");
        }
        KeyPair kp;
        kp.publicKey.data.resize(crypto_sign_PUBLICKEYBYTES);
        kp.privateKey.data.resize(crypto_sign_SECRETKEYBYTES);
        if (crypto_sign_seed_keypair(kp.publicKey.data.data(), kp.privateKey.data.data(), seed) != 0) {
            throw RuntimeError("Seed expansion failed.");
        }
        return kp;
    }

    PublicKey Crypto::derive_public_key(const uint8_t* private_key, size_t len) {
        if (len != crypto_sign_SECRETKEYBYTES) {
            throw InvalidArgument("Private key must be exactly 64 bytes.");
        }
        PublicKey pk;
        pk.data.resize(crypto_sign_PUBLICKEYBYTES);
        crypto_sign_ed25519_sk_to_pk(pk.data.data(), private_key);
        return pk;
    }

    Signature Crypto::sign(const byte_vector& message, const PrivateKey& private_key) {
        if (private_key.data.size() != crypto_sign_SECRETKEYBYTES) {
            throw InvalidArgument("Invalid private key size for signing.");
        }
        Signature sig;
        sig.data.resize(crypto_sign_BYTES);
        crypto_sign_detached(sig.data.data(), nullptr, message.data(), message.size(), private_key.data.data());
        return sig;
    }

    bool Crypto::verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key) {
        if (signature.data.size() != crypto_sign_BYTES || public_key.data.size() != crypto_sign_PUBLICKEYBYTES) {
            return false;  // Invalid sizes
        }
        return crypto_sign_verify_detached(
                   signature.data.data(), message.data(), message.size(), public_key.data.data()) == 0;
    }

    Crypto::SessionKeys Crypto::client_compute_session_keys(const KeyPair& client_kx_kp,
                                                            const PublicKey& server_eph_pk) {
        if (client_kx_kp.publicKey.data.size() != crypto_kx_PUBLICKEYBYTES ||
            client_kx_kp.privateKey.data.size() != crypto_kx_SECRETKEYBYTES ||
            server_eph_pk.data.size() != crypto_kx_PUBLICKEYBYTES) {
            throw InvalidArgument("Invalid key sizes for client session key computation.");
        }

        SessionKeys keys;
        keys.rx.resize(crypto_kx_SESSIONKEYBYTES);
        keys.tx.resize(crypto_kx_SESSIONKEYBYTES);

        if (crypto_kx_client_session_keys(keys.rx.data(),
                                          keys.tx.data(),
                                          client_kx_kp.publicKey.data.data(),
                                          client_kx_kp.privateKey.data.data(),
                                          server_eph_pk.data.data()) != 0) {
            throw RuntimeError("Failed to compute client session keys.");
        }
        return keys;
    }

    Crypto::SessionKeys Crypto::server_compute_session_keys(const KeyPair& server_kx_kp,
                                                            const PublicKey& client_eph_pk) {
        if (server_kx_kp.publicKey.data.size() != crypto_kx_PUBLICKEYBYTES ||
            server_kx_kp.privateKey.data.size() != crypto_kx_SECRETKEYBYTES ||
            client_eph_pk.data.size() != crypto_kx_PUBLICKEYBYTES) {
            throw InvalidArgument("Invalid key sizes for server session key computation.");
        }

        SessionKeys keys;
        keys.rx.resize(crypto_kx_SESSIONKEYBYTES);
        keys.tx.resize(crypto_kx_SESSIONKEYBYTES);

        if (crypto_kx_server_session_keys(keys.rx.data(),
                                          keys.tx.data(),
                                          server_kx_kp.publicKey.data.data(),
                                          server_kx_kp.privateKey.data.data(),
                                          client_eph_pk.data.data()) != 0) {
            throw RuntimeError("Failed to compute server session keys.");
        }
        return keys;
    }

    EncryptedPacket Crypto::encrypt(const Payload& payload, uint64_t counter, const byte_vector& key) {
        if (key.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
            throw InvalidArgument("Invalid key size for encryption.");
        }

        byte_vector plaintext = payload.serialize();
        byte_vector nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());

        uint64_t be_counter = htonll_local(counter);

        EncryptedPacket packet;
        // Size: Nonce + Counter + Ciphertext + Auth Tag
        packet.resize(nonce.size() + sizeof(be_counter) + plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

        unsigned long long ciphertext_len;
        crypto_aead_chacha20poly1305_ietf_encrypt(packet.data() + nonce.size() + sizeof(be_counter),
                                                  &ciphertext_len,
                                                  plaintext.data(),
                                                  plaintext.size(),
                                                  reinterpret_cast<unsigned char*>(&be_counter),
                                                  sizeof(be_counter),
                                                  nullptr,  // nsec is not used
                                                  nonce.data(),
                                                  key.data());

        // Manually construct the final packet
        std::copy(nonce.begin(), nonce.end(), packet.begin());
        std::copy(reinterpret_cast<uint8_t*>(&be_counter),
                  reinterpret_cast<uint8_t*>(&be_counter) + sizeof(be_counter),
                  packet.begin() + nonce.size());

        return packet;
    }

    Crypto::DecryptedResult Crypto::decrypt(const EncryptedPacket& packet, const byte_vector& key) {
        if (key.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
            throw InvalidArgument("Invalid key size for decryption.");
        }

        constexpr size_t NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
        constexpr size_t COUNTER_SIZE = sizeof(uint64_t);
        constexpr size_t HEADER_SIZE = NONCE_SIZE + COUNTER_SIZE;

        if (packet.size() < HEADER_SIZE + crypto_aead_chacha20poly1305_ietf_ABYTES) {
            throw RuntimeError("Packet too small to be valid.");
        }

        // Deconstruct the packet
        byte_vector nonce(packet.begin(), packet.begin() + NONCE_SIZE);
        uint64_t be_counter;
        std::copy(packet.begin() + NONCE_SIZE, packet.begin() + HEADER_SIZE, reinterpret_cast<uint8_t*>(&be_counter));
        uint64_t received_counter = ntohll_local(be_counter);

        const unsigned char* ciphertext_with_tag = packet.data() + HEADER_SIZE;
        size_t ciphertext_with_tag_len = packet.size() - HEADER_SIZE;

        byte_vector decrypted_payload_data;
        decrypted_payload_data.resize(ciphertext_with_tag_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
        unsigned long long decrypted_len;

        if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted_payload_data.data(),
                                                      &decrypted_len,
                                                      nullptr,  // nsec is not used
                                                      ciphertext_with_tag,
                                                      ciphertext_with_tag_len,
                                                      reinterpret_cast<const unsigned char*>(&be_counter),
                                                      sizeof(be_counter),
                                                      nonce.data(),
                                                      key.data()) != 0) {
            throw RuntimeError("Failed to decrypt message. Authentication tag may be invalid.");
        }

        decrypted_payload_data.resize(decrypted_len);  // Adjust to actual decrypted size

        DecryptedResult result;
        result.payload = Payload::deserialize(decrypted_payload_data);
        result.counter = received_counter;

        return result;
    }

}  // namespace ObscuraProto
