#include "obscuraproto/session.hpp"

#include <sodium.h>

#include <algorithm>
#include <optional>

#include "obscuraproto/errors.hpp"

namespace ObscuraProto {

    Session::Session(Role role, KeyPair server_sign_key, std::vector<Version> supported_versions)
        : role_(role),
          server_sign_key_(std::move(server_sign_key)),
          supported_versions_(std::move(supported_versions)) {
    }

    Session::~Session() {
        wipe_keys();
    }

    void Session::wipe_keys() {
        if (session_keys_) {
            secure_wipe(session_keys_->rx);
            secure_wipe(session_keys_->tx);
            session_keys_.reset();
        }
        if (ephemeral_kx_kp_) {
            ephemeral_kx_kp_->privateKey.data.clear();
            ephemeral_kx_kp_.reset();
        }
    }

    void Session::set_client_identity_key(KeyPair identity_kp) {
        if (role_ != Role::CLIENT) {
            throw LogicError("Only clients can set an identity key.");
        }
        client_identity_kp_ = std::move(identity_kp);
    }

    // --- Handshake ---

    ClientHello Session::client_initiate_handshake() {
        if (role_ != Role::CLIENT) {
            throw LogicError("Only clients can initiate a handshake.");
        }

        // 1. Generate an ephemeral key pair for this session
        ephemeral_kx_kp_ = std::make_unique<KeyPair>(Crypto::generate_kx_keypair());

        // 2. Create the ClientHello message
        ClientHello hello;
        hello.supported_versions = supported_versions_;
        hello.ephemeral_pk = ephemeral_kx_kp_->publicKey;

        // 3. Include client identity if set
        if (client_identity_kp_.has_value()) {
            hello.has_client_identity = true;
            hello.identity_pk = client_identity_kp_->publicKey;
            hello.identity_sig = Crypto::sign(hello.ephemeral_pk.data, client_identity_kp_->privateKey);
        }

        return hello;
    }

    ServerHello Session::server_respond_to_handshake(const ClientHello& client_hello) {
        if (role_ != Role::SERVER) {
            throw LogicError("Only servers can respond to a handshake.");
        }

        // 1. Select a compatible protocol version.
        auto chosen_version = VersionNegotiator::negotiate(client_hello.supported_versions, supported_versions_);

        if (!chosen_version) {
            throw RuntimeError("Client and server have no supported protocol versions in common.");
        }
        selected_version_ = *chosen_version;

        // 2. Verify client identity if provided
        if (client_hello.has_client_identity) {
            bool sig_valid =
                Crypto::verify(client_hello.identity_sig, client_hello.ephemeral_pk.data, client_hello.identity_pk);
            if (!sig_valid) {
                throw RuntimeError("Client identity signature verification failed.");
            }
            peer_identity_ = client_hello.identity_pk;
        }

        // 3. Generate an ephemeral key pair for this session
        ephemeral_kx_kp_ = std::make_unique<KeyPair>(Crypto::generate_kx_keypair());

        // 4. Sign our ephemeral public key with our long-term signing key
        Signature signature = Crypto::sign(ephemeral_kx_kp_->publicKey.data, server_sign_key_.privateKey);

        // 5. Compute the session keys
        session_keys_ = std::make_unique<Crypto::SessionKeys>(
            Crypto::server_compute_session_keys(*ephemeral_kx_kp_, client_hello.ephemeral_pk));

        // 6. Create the ServerHello message
        ServerHello hello;
        hello.selected_version = *selected_version_;
        hello.ephemeral_pk = ephemeral_kx_kp_->publicKey;
        hello.signature = signature;

        handshake_complete_ = true;  // Server is ready after this step
        return hello;
    }

    void Session::client_finalize_handshake(const ServerHello& server_hello) {
        if (role_ != Role::CLIENT) {
            throw LogicError("Only clients can finalize a handshake.");
        }
        if (!ephemeral_kx_kp_) {
            throw LogicError("client_initiate_handshake must be called first.");
        }

        // 1. Verify that the server selected a version we support
        bool version_is_supported = false;
        for (const auto& supported_ver : supported_versions_) {
            if (server_hello.selected_version == supported_ver) {
                version_is_supported = true;
                break;
            }
        }
        if (!version_is_supported) {
            throw RuntimeError("Server selected a protocol version that the client does not support.");
        }
        selected_version_ = server_hello.selected_version;

        // 2. Verify the signature of the server's ephemeral key
        bool signature_valid =
            Crypto::verify(server_hello.signature, server_hello.ephemeral_pk.data, server_sign_key_.publicKey);
        if (!signature_valid) {
            throw RuntimeError("Server's signature for its ephemeral key is invalid.");
        }

        // 3. Compute the session keys
        session_keys_ = std::make_unique<Crypto::SessionKeys>(
            Crypto::client_compute_session_keys(*ephemeral_kx_kp_, server_hello.ephemeral_pk));

        handshake_complete_ = true;  // Client is ready after this step
    }

    bool Session::is_handshake_complete() const {
        return handshake_complete_;
    }

    std::optional<Version> Session::get_selected_version() const {
        return selected_version_;
    }

    bool Session::has_peer_identity() const {
        return peer_identity_.has_value();
    }

    std::optional<PublicKey> Session::get_peer_identity() const {
        return peer_identity_;
    }

    // --- Data Transfer ---

    EncryptedPacket Session::encrypt_payload(const Payload& payload) {
        if (!handshake_complete_) {
            throw LogicError("Handshake must be complete before sending data.");
        }

        // Always use the 'tx' key for encryption.
        const auto& key = session_keys_->tx;

        send_counter_++;
        return Crypto::encrypt(payload, send_counter_, key);
    }

    Payload Session::decrypt_packet(const EncryptedPacket& packet) {
        if (!handshake_complete_) {
            throw LogicError("Handshake must be complete before receiving data.");
        }

        // Always use the 'rx' key for decryption.
        const auto& key = session_keys_->rx;

        // Decrypt the packet to get the payload and the counter.
        Crypto::DecryptedResult result = Crypto::decrypt(packet, key);

        // Now, perform the anti-replay check.
        // The received counter must be greater than the last one we processed.
        if (result.counter <= recv_counter_) {
            throw RuntimeError("Counter mismatch. Possible replay attack.");
        }

        // If decryption and counter check were successful, we can now update our counter.
        recv_counter_ = result.counter;

        return result.payload;
    }

}  // namespace ObscuraProto
