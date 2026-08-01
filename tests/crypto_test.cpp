#include "obscuraproto/crypto.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "obscuraproto/packet.hpp"
#include "obscuraproto/session.hpp"

TEST(SessionTest, HandshakeAndEncryptDecrypt) {
    // 1. Initialize the crypto library
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    // 2. Setup server and client
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    // 3. Handshake
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);

    ASSERT_TRUE(server_session.is_handshake_complete());
    ASSERT_TRUE(client_session.is_handshake_complete());

    // 4. Data Transfer: Client -> Server
    uint64_t timestamp = 1678886400000;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
                                               .add_param("my_username")
                                               .add_param("my_very_secret_password")
                                               .add_param(timestamp)
                                               .build();

    // 5. Encrypt on client
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);

    // 6. Decrypt on server
    ObscuraProto::Payload decrypted_payload;
    ASSERT_NO_THROW({ decrypted_payload = server_session.decrypt_packet(packet_to_send); });

    // 7. Verify decrypted data
    ASSERT_EQ(decrypted_payload.op_code, client_payload.op_code);

    ObscuraProto::PayloadReader reader(decrypted_payload);
    auto username = reader.read_param<std::string>();
    auto password = reader.read_param<std::string>();
    auto received_timestamp = reader.read_param<uint64_t>();

    ASSERT_EQ(username, "my_username");
    ASSERT_EQ(password, "my_very_secret_password");
    ASSERT_EQ(received_timestamp, timestamp);
}

TEST(SessionTest, DecryptionFailure) {
    // 1. Initialize and handshake
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;
    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    client_session.client_finalize_handshake(server_hello);
    ASSERT_TRUE(client_session.is_handshake_complete());

    // 2. Create a payload and encrypt it
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001).add_param("some data").build();
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);

    // 3. Create a second server session with a different key
    auto server_long_term_key_2 = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::Session server_session_2(ObscuraProto::Role::SERVER, server_long_term_key_2);
    // This session did not perform the handshake with the client, so it has different session keys.

    // 4. Try to decrypt with the wrong session
    ASSERT_THROW(server_session_2.decrypt_packet(packet_to_send), ObscuraProto::LogicError);

    // 5. Corrupt the packet and try to decrypt
    packet_to_send[packet_to_send.size() - 1] ^= 0xFF;  // Flip some bits in the tag
    ASSERT_THROW(server_session.decrypt_packet(packet_to_send), ObscuraProto::RuntimeError);
}

TEST(SessionTest, HandshakeFailure) {
    // 1. Initialize
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    // 2. Setup server and client with mismatched keys
    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    auto wrong_server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = wrong_server_long_term_key.publicKey;  // Client has the wrong key

    ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);
    ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);

    // 3. Handshake
    auto client_hello = client_session.client_initiate_handshake();
    auto server_hello = server_session.server_respond_to_handshake(client_hello);

    // 4. Client should fail to finalize the handshake
    ASSERT_THROW(client_session.client_finalize_handshake(server_hello), ObscuraProto::RuntimeError);
    ASSERT_FALSE(client_session.is_handshake_complete());
}

// A deterministic 32-byte Ed25519 seed for reproducible tests.
static std::vector<uint8_t> make_test_seed() {
    std::vector<uint8_t> seed(32);
    for (size_t i = 0; i < seed.size(); ++i) {
        seed[i] = static_cast<uint8_t>(0xA0 + i);
    }
    return seed;
}

// Converts a hex string into a byte vector (used for fixed external test vectors).
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

TEST(CryptoTest, KeypairFromSeed) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto seed = make_test_seed();
    auto kp = ObscuraProto::Crypto::keypair_from_seed(seed.data(), seed.size());
    ASSERT_EQ(kp.publicKey.data.size(), crypto_sign_PUBLICKEYBYTES);
    ASSERT_EQ(kp.privateKey.data.size(), crypto_sign_SECRETKEYBYTES);

    // Invalid seed lengths must throw.
    std::vector<uint8_t> short_seed(31, 0x01);
    ASSERT_THROW(ObscuraProto::Crypto::keypair_from_seed(short_seed.data(), short_seed.size()),
                 ObscuraProto::InvalidArgument);
    std::vector<uint8_t> long_seed(33, 0x01);
    ASSERT_THROW(ObscuraProto::Crypto::keypair_from_seed(long_seed.data(), long_seed.size()),
                 ObscuraProto::InvalidArgument);
}

TEST(CryptoTest, DerivePublicKey) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto seed = make_test_seed();
    auto kp = ObscuraProto::Crypto::keypair_from_seed(seed.data(), seed.size());

    auto pk = ObscuraProto::Crypto::derive_public_key(kp.privateKey.data.data(), kp.privateKey.data.size());
    ASSERT_EQ(pk.data.size(), crypto_sign_PUBLICKEYBYTES);

    // Invalid private key length must throw.
    std::vector<uint8_t> short_sk(63, 0x01);
    ASSERT_THROW(ObscuraProto::Crypto::derive_public_key(short_sk.data(), short_sk.size()),
                 ObscuraProto::InvalidArgument);
}

TEST(CryptoTest, SeedConsistency) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    auto seed = make_test_seed();
    auto kp = ObscuraProto::Crypto::keypair_from_seed(seed.data(), seed.size());

    // Public key derived from the private key must match the keypair's public key.
    auto derived_pk = ObscuraProto::Crypto::derive_public_key(kp.privateKey.data.data(), kp.privateKey.data.size());
    ASSERT_EQ(derived_pk, kp.publicKey);

    // The derived keypair must be usable end-to-end (sign + verify).
    ObscuraProto::byte_vector message = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto sig = ObscuraProto::Crypto::sign(message, kp.privateKey);
    ASSERT_TRUE(ObscuraProto::Crypto::verify(sig, message, derived_pk));

    // A different seed must produce a different keypair.
    std::vector<uint8_t> other_seed(32, 0x42);
    auto other_kp = ObscuraProto::Crypto::keypair_from_seed(other_seed.data(), other_seed.size());
    ASSERT_NE(other_kp.publicKey, kp.publicKey);
}

// RFC 8032 (Ed25519) Test 1: fixed seed, public key and private key (seed || pk).
// Pins external consistency of seed expansion against the RFC reference vector,
// not just internal keypair consistency.
TEST(CryptoTest, KeypairFromSeedMatchesRfc8032) {
    ASSERT_EQ(ObscuraProto::Crypto::init(), 0);

    const std::string seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const std::string pk_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    auto seed = hex_to_bytes(seed_hex);
    auto expected_pk = hex_to_bytes(pk_hex);
    auto expected_sk = seed;
    expected_sk.insert(expected_sk.end(), expected_pk.begin(), expected_pk.end());

    auto kp = ObscuraProto::Crypto::keypair_from_seed(seed.data(), seed.size());
    ASSERT_EQ(kp.publicKey.data, expected_pk);
    std::vector<uint8_t> actual_sk(kp.privateKey.data.begin(), kp.privateKey.data.end());
    ASSERT_EQ(actual_sk, expected_sk);

    // The public key must also be recoverable from the RFC 8032 private key.
    auto derived_pk = ObscuraProto::Crypto::derive_public_key(expected_sk.data(), expected_sk.size());
    ASSERT_EQ(derived_pk.data, expected_pk);
}
