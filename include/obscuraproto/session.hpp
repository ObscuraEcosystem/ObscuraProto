#ifndef OBSCURAPROTO_SESSION_HPP
#define OBSCURAPROTO_SESSION_HPP

#include <memory>

#include "crypto.hpp"
#include "handshake_messages.hpp"
#include "packet.hpp"
#include "version.hpp"

namespace ObscuraProto {

    enum class Role { CLIENT, SERVER };

    /**
     * @brief Manages the state and logic for a single ObscuraProto session.
     */
    class Session {
    public:
        /**
         * @brief Construct a new Session object.
         * @param role Whether this session belongs to a client or a server.
         * @param server_sign_key For a server, its long-term signing key pair.
         *                        For a client, a key pair with only the public key part filled.
         * @param supported_versions The list of protocol versions this session supports,
         *                           in descending order of preference.
         *                           Defaults to the global SUPPORTED_VERSIONS.
         */
        Session(Role role, KeyPair server_sign_key, std::vector<Version> supported_versions = SUPPORTED_VERSIONS);
        ~Session();

        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
        Session(Session&&) = default;
        Session& operator=(Session&&) = default;

        /**
         * @brief [CLIENT] Sets the identity key pair for client authentication.
         * @param identity_kp The client's Ed25519 key pair.
         */
        void set_client_identity_key(KeyPair identity_kp);

        // --- Handshake Methods ---

        /**
         * @brief [CLIENT] Initiates the handshake.
         * @return A ClientHello message to be sent to the server.
         */
        ClientHello client_initiate_handshake();

        /**
         * @brief [SERVER] Responds to a client's initiation request.
         * @param client_hello The message received from the client.
         * @return A ServerHello message to be sent back to the client.
         * @throws ObscuraProto::RuntimeError if no compatible version is found, keys are invalid,
         *                                    or client identity signature verification fails.
         */
        ServerHello server_respond_to_handshake(const ClientHello& client_hello);

        /**
         * @brief [CLIENT] Finalizes the handshake after receiving the server's response.
         * @param server_hello The message received from the server.
         * @throws ObscuraProto::RuntimeError if the server's signature is invalid or keys can't be computed.
         */
        void client_finalize_handshake(const ServerHello& server_hello);

        // --- Data Transfer Methods ---

        /**
         * @brief Encrypts a payload to be sent over the secure channel.
         * @param payload The application data to send.
         * @return An encrypted packet ready for transport.
         */
        EncryptedPacket encrypt_payload(const Payload& payload);

        /**
         * @brief Decrypts a received packet.
         * @param packet The packet received from the transport.
         * @return The decrypted application payload.
         * @throws ObscuraProto::RuntimeError on decryption or counter failure.
         */
        Payload decrypt_packet(const EncryptedPacket& packet);

        /**
         * @brief Checks if the handshake has been successfully completed.
         */
        bool is_handshake_complete() const;

        /**
         * @brief Gets the negotiated protocol version.
         * @return The selected version, or std::nullopt if handshake is not complete.
         */
        std::optional<Version> get_selected_version() const;

        // --- Client Identity Methods ---

        /**
         * @brief Checks if the peer provided a verified identity.
         * @return True if the client authenticated with an Ed25519 key.
         */
        bool has_peer_identity() const;

        /**
         * @brief Gets the verified public key of the peer.
         * @return The peer's Ed25519 public key, or std::nullopt if not authenticated.
         */
        std::optional<PublicKey> get_peer_identity() const;

    private:
        void wipe_keys();

        Role role_;
        bool handshake_complete_ = false;
        std::optional<Version> selected_version_ = std::nullopt;
        std::vector<Version> supported_versions_;

        // Long-term signing key. For the server, this contains the private key.
        // For the client, this contains the server's public key.
        KeyPair server_sign_key_;

        // Ephemeral key pair for the current session's key exchange.
        std::unique_ptr<KeyPair> ephemeral_kx_kp_;

        // Session keys (derived from ECDH)
        std::unique_ptr<Crypto::SessionKeys> session_keys_;

        // Client identity (for client-side, the keypair; for server-side, the verified peer public key)
        std::optional<KeyPair> client_identity_kp_;
        std::optional<PublicKey> peer_identity_;

        // Message counters
        uint64_t send_counter_ = 0;
        uint64_t recv_counter_ = 0;
    };

}  // namespace ObscuraProto

#endif  // OBSCURAPROTO_SESSION_HPP
