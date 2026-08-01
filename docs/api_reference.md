# ObscuraProto API Reference

This document provides a detailed description of every public component in the ObscuraProto library.

---

## `errors.hpp`

Defines the hierarchy of exceptions used in the library.

### `class ObscuraProto::Exception`
The base class for all library exceptions. Inherits from `std::exception`.

#### `virtual const char* what() const noexcept override`
Returns the error message.

---

### `class ObscuraProto::RuntimeError`
An exception thrown for runtime errors.
- **Examples:** decryption failure, invalid signature, key exchange error.

---

### `class ObscuraProto::LogicError`
An exception indicating incorrect API usage.
- **Examples:** attempting to encrypt data before the handshake is complete, calling a server-only method on the client side.

---

### `class ObscuraProto::InvalidArgument`
An exception thrown when incorrect arguments are passed to a function. Inherits from `LogicError`.
- **Examples:** passing a key of the wrong size.

---

### `class ObscuraProto::TimeoutError`
An exception thrown when a request exceeds its timeout budget. Inherits from `RuntimeError`.
- **Raised by:** `sync_request()` (via `wait_for`) when the timeout expires before the response arrives; delivered to `async_request()` futures whose deadline passed — `std::future::get()` rethrows it.

---

## `keys.hpp`

Defines basic structures for storing cryptographic keys and signatures.

### `struct ObscuraProto::PublicKey`
Represents a public key.
- `std::vector<uint8_t> data`: Raw bytes of the key.
- `bool operator==(const PublicKey& other) const`: Compares two public keys by their data.
- `bool operator!=(const PublicKey& other) const`: Inequality comparison.
- `bool operator<(const PublicKey& other) const`: Lexicographic comparison of key data (for use in `std::map`).

### `struct ObscuraProto::PrivateKey`
Represents a private key.
- `std::vector<uint8_t> data`: Raw bytes of the key.

### `struct ObscuraProto::KeyPair`
Represents a pair consisting of a public and a private key.
- `PublicKey publicKey`: The public key.
- `PrivateKey privateKey`: The private key.

### `struct ObscuraProto::Signature`
Represents a digital signature.
- `std::vector<uint8_t> data`: Raw bytes of the signature.

---

## `version.hpp`

Defines constants and types for managing the protocol version.

### `using Version = uint16_t`
An alias for the protocol version type. Version `1.0` is represented as `0x0100`.

### `const std::vector<Version> SUPPORTED_VERSIONS`
A list of protocol versions supported by the current library version.

---

## `packet.hpp`

Defines the structure of the payload before encryption and after decryption, and provides helper classes for building and parsing payloads.

### `using byte_vector = std::vector<uint8_t>`
An alias for representing a byte array.

### `using EncryptedPacket = byte_vector`
An alias for an encrypted packet. Its content is opaque and ready for network transmission.

### `class ObscuraProto::Payload`
A class that holds the operation code and serialized parameters.

- `OpCode op_code`: A 16-bit operation code that defines the message type.
- `byte_vector parameters`: Serialized parameters for the given operation.

#### `byte_vector serialize() const`
Serializes the entire `Payload` object (op code + parameters) into a single byte array, ready for encryption.

#### `static Payload deserialize(const byte_vector& data)`
Deserializes a byte array back into a `Payload` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

### `class ObscuraProto::PayloadBuilder`
A helper class for fluently constructing `Payload` objects with various parameters.

#### `explicit PayloadBuilder(Payload::OpCode op_code)`
Constructor. Initializes the builder with the specified operation code.

#### `PayloadBuilder& add_param(const T& param)`
Adds a parameter of a given type. The library has overloads for `std::string`, `byte_vector`, `bool`, `float`, `double`, and all standard integer types (`int8_t`, `uint8_t`, `int16_t`, `uint16_t`, etc.). All parameters are serialized using a length-prefix method.
- **Returns:** A reference to the builder for method chaining.
- **Throws:** `RuntimeError` if a string or byte_vector parameter's size exceeds `UINT16_MAX`.

#### `Payload build()`
Finalizes the construction and returns the `Payload` object.

---

### `class ObscuraProto::PayloadReader`
A helper class for sequentially extracting parameters from a received `Payload`.

#### `explicit PayloadReader(const Payload& payload)`
Constructor. Initializes the reader with the `parameters` field from a `Payload` object.

#### `template<typename T> T read_param()`
Extracts the next parameter and casts it to the specified template type `T`. The method supports `std::string`, `byte_vector`, `bool`, `float`, `double`, and all standard integer types.
- **Example:** `std::string name = reader.read_param<std::string>();`, `int score = reader.read_param<int32_t>();`
- **Returns:** The parameter cast to type `T`.
- **Throws:** `RuntimeError` if the data is malformed, insufficient, or if the stored parameter size does not match the size of the requested type `T`.

#### `bool has_more() const`
Checks if there are more parameters to read in the payload.
- **Returns:** `true` if there are unread parameters, `false` otherwise.

---

## `crypto.hpp`

A static class that provides all low-level cryptographic functions.

### `static int init()`
Initializes the cryptographic library (libsodium). **Must be called once** at application startup.
- **Returns:** `0` on success, `-1` on error.

### `static KeyPair generate_kx_keypair()`
Generates a key pair (X25519) for key exchange using the Diffie-Hellman (ECDH) algorithm.

### `static KeyPair generate_sign_keypair()`
Generates a key pair (Ed25519) for creating and verifying digital signatures.

### `static KeyPair keypair_from_seed(const uint8_t* seed, size_t len)`
Deterministically derives an Ed25519 key pair from a 32-byte seed (`crypto_sign_seed_keypair`).
- `seed`: The 32-byte seed (`crypto_sign_SEEDBYTES`).
- `len`: The seed length in bytes (must be exactly 32).
- **Returns:** A `KeyPair` object.
- **Throws:** `InvalidArgument` if `len` is not exactly 32; `RuntimeError` if seed expansion fails.

### `static PublicKey derive_public_key(const uint8_t* private_key, size_t len)`
Derives the Ed25519 public key from a 64-byte private key (`crypto_sign_ed25519_sk_to_pk`).
- `private_key`: The 64-byte private key (`seed || public`).
- `len`: The private key length in bytes (must be exactly 64).
- **Returns:** A `PublicKey` object.
- **Throws:** `InvalidArgument` if `len` is not exactly 64.

### `static Signature sign(const byte_vector& message, const PrivateKey& private_key)`
Creates a digital signature for a message.
- **Throws:** `InvalidArgument` if the private key size is incorrect.

### `static bool verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key)`
Verifies a digital signature.
- **Returns:** `true` if the signature is valid, otherwise `false`.

### `struct SessionKeys`
A structure for storing session keys obtained after the handshake.
- `byte_vector rx`: The key for decrypting incoming messages.
- `byte_vector tx`: The key for encrypting outgoing messages.

### `static SessionKeys client_compute_session_keys(...)`
**For the client.** Computes session keys based on its own ephemeral key pair and the server's ephemeral public key.
- **Throws:** `InvalidArgument` for incorrect key sizes, `RuntimeError` on computation failure.

### `static SessionKeys server_compute_session_keys(...)`
**For the server.** Computes session keys based on its own ephemeral key pair and the client's ephemeral public key.
- **Throws:** `InvalidArgument` for incorrect key sizes, `RuntimeError` on computation failure.

### `static EncryptedPacket encrypt(const Payload& payload, uint64_t counter, const byte_vector& key)`
Encrypts a `Payload` using ChaCha20-Poly1305.
- `counter`: A message counter for replay attack protection. It is included in the packet as associated data (not encrypted, but protected by the authentication tag).
- **Returns:** An `EncryptedPacket` in the format `[Nonce][Counter][Ciphertext+Tag]`.
- **Throws:** `InvalidArgument` for an incorrect key size.

### `struct DecryptedResult`
The result of a successful decryption.
- `Payload payload`: The decrypted payload.
- `uint64_t counter`: The counter extracted from the packet.

### `static DecryptedResult decrypt(const EncryptedPacket& packet, const byte_vector& key)`
Decrypts a packet. Verifies the authentication tag.
- **Returns:** `DecryptedResult` on success.
- **Throws:** `InvalidArgument` for an incorrect key size, `RuntimeError` on decryption failure (invalid tag, corrupted data).

---

## `handshake_messages.hpp`

Defines the structures used during the handshake phase.

### `struct ObscuraProto::ClientHello`
Represents the initial message sent by the client.
- `std::vector<Version> supported_versions`: A list of protocol versions the client supports.
- `PublicKey ephemeral_pk`: The client's ephemeral public key for this session.
- `bool has_client_identity`: Whether the client included an Ed25519 identity key and signature.
- `PublicKey identity_pk`: The client's Ed25519 public key (only valid if `has_client_identity` is `true`).
- `Signature identity_sig`: The Ed25519 signature over `ephemeral_pk.data` (only valid if `has_client_identity` is `true`).

#### `byte_vector serialize() const`
Serializes the `ClientHello` object into a byte vector for network transmission.

#### `static ClientHello deserialize(const byte_vector& data)`
Deserializes a byte vector back into a `ClientHello` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

### `struct ObscuraProto::ServerHello`
Represents the server's response to a `ClientHello`.
- `Version selected_version`: The protocol version selected by the server.
- `PublicKey ephemeral_pk`: The server's ephemeral public key for this session.
- `Signature signature`: The server's signature over its ephemeral public key, for authentication.

#### `byte_vector serialize() const`
Serializes the `ServerHello` object into a byte vector for network transmission.

#### `static ServerHello deserialize(const byte_vector& data)`
Deserializes a byte vector back into a `ServerHello` object.
- **Throws:** `RuntimeError` if the data is corrupted or its size is insufficient.

---

## Network Wrappers (`ws_client.hpp`, `ws_server.hpp`)

These files provide high-level wrappers for running the ObscuraProto protocol over WebSockets. This is the recommended API for most use cases.

### `namespace ObscuraProto::net`
Contains all network-related classes.

---

### `class ObscuraProto::net::WsServerWrapper`
A wrapper that runs a WebSocket server to handle multiple secure client connections.

#### `WsServerWrapper(KeyPair server_sign_key)`
Constructor.
- `server_sign_key`: The server's long-term signing key pair (public and private).

#### `void run(uint16_t port)`
Starts the server in a new thread, listening for connections on the specified port.

#### `void stop()`
Stops the server and disconnects all clients.

#### `void send(WsConnectionHdl hdl, const Payload& payload)`
Encrypts and sends a `Payload` to a specific client identified by their connection handle `hdl`.

#### `void send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload)`
Sends a response to a client for a previously received request. The `payload` provided here is the application-level response. The library handles wrapping it with the internal `RESPONSE_OP_CODE` (`0xFFFF`) and the `request_id`.
- `hdl`: The connection handle of the client to send the response to.
- `request_id`: The unique ID of the request this response is for, extracted from the incoming request payload.
- `payload`: The application-level `Payload` containing the actual response data.

#### `std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload)`
Sends a `Payload` as a request to a specific client and returns a `std::future` that will be fulfilled with the client's response. The default timeout from `config_.timeouts.request_ms` (30000 ms) applies; a `0` value in the config means unlimited, and `timeouts.enabled: false` disables the timeout enforcement.
- `hdl`: The connection handle of the client to send the request to.
- `payload`: The application-level `Payload` to send as a request.
- **Returns:** A `std::future<Payload>` that will eventually hold the client's application-level response. On timeout the future resolves with `ObscuraProto::TimeoutError` (`get()` rethrows it).
- **Throws:** `LogicError` if the session is not ready.

#### `std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload, uint32_t timeout_ms)`
Same as `async_request(hdl, payload)` but with an explicit per-request timeout.
- `timeout_ms`: Maximum time to wait for the response in milliseconds. `0` = use the default from `config_.timeouts.request_ms`; unlimited = `request_ms: 0` in the config or `timeouts.enabled: false`.
- **Returns:** A `std::future<Payload>` that will eventually hold the client's application-level response. On timeout the future resolves with `ObscuraProto::TimeoutError`.
- **Throws:** `LogicError` if the session is not ready.

#### `Payload sync_request(WsConnectionHdl hdl, const Payload& payload)`
Sends a synchronous request to a specific client and blocks until the response arrives.
- **Throws:** `LogicError` if the session is not ready; `ObscuraProto::TimeoutError` if the default timeout (`config_.timeouts.request_ms`, 30000 ms) expires before the response arrives. A `0` value in the config means unlimited, `timeouts.enabled: false` disables timeout enforcement.

#### `Payload sync_request(WsConnectionHdl hdl, const Payload& payload, uint32_t timeout_ms)`
Sends a synchronous request with an explicit per-request timeout and blocks until the response arrives.
- `timeout_ms`: Maximum time to wait for the response in milliseconds. `0` = use the default from `config_.timeouts.request_ms`; unlimited = `request_ms: 0` in the config or `timeouts.enabled: false`.
- **Throws:** `LogicError` if the session is not ready; `ObscuraProto::TimeoutError` if the timeout expires before the response arrives.

#### `void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Registers a handler for a specific operation code. When a payload with a matching `op_code` is received, this specific callback will be invoked.
- `op_code`: The operation code to handle.
- `callback`: The function to call.

#### `void register_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Registers a simplified handler for a request-response interaction. This is the recommended way to handle requests. The library automatically handles reading the request ID and sending the response.
- `op_code`: The operation code of the request to handle.
- `callback`: A function that takes a `PayloadReader&` to read the request parameters and must return a `Payload` object, which will be sent as the response.
- **Callback signature:** `std::function<Payload(WsConnectionHdl, PayloadReader&)>`

#### `void set_default_payload_handler(OnPayloadCallback callback)`
Sets a callback function to be invoked when a `Payload` is received from any client and there is no specific handler registered for its `op_code`. This acts as a catch-all handler.
- **Callback signature:** `std::function<void(WsConnectionHdl, Payload)>`

#### `void set_on_open_callback(OnOpenCallback callback)`
Registers a callback invoked when a new WebSocket connection is established. The callback fires immediately after the TCP/WebSocket handshake, before the ObscuraProto cryptographic handshake.
- `callback`: A function that receives the connection handle of the newly connected client.
- **Callback signature:** `std::function<void(WsConnectionHdl)>`

#### `void set_on_close_callback(OnCloseCallback callback)`
Registers a callback invoked when a WebSocket connection is closed. The callback fires while the connection handle is still valid, before internal cleanup of sessions, streams, and pending requests.
- `callback`: A function that receives the connection handle of the disconnected client.
- **Callback signature:** `std::function<void(WsConnectionHdl)>`

#### `void set_on_payload_callback(OnPayloadCallback callback)`
**Deprecated.** This method now calls `set_default_payload_handler`. Use `set_default_payload_handler` for clarity or `register_op_handler` for specific op-codes.

#### `void send_anonymous(WsConnectionHdl hdl, const Payload& payload)`
Encrypts and sends a `Payload` to an anonymous client (one that connected without identity authentication).
- **Throws:** `LogicError` if the anonymous session is not ready.

#### `void register_anon_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Registers a handler for a specific operation code from **anonymous sessions** only.
- `op_code`: The operation code to handle.
- `callback`: The function to call. Signature: `void(WsConnectionHdl, Payload)`.

#### `void register_anon_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Registers a simplified request-response handler for **anonymous sessions** only. The library automatically handles reading the request ID and sending the response.
- `op_code`: The operation code of the request to handle.
- `callback`: A function that takes a `PayloadReader&` to read the request parameters and must return a `Payload` object.
- **Callback signature:** `std::function<Payload(WsConnectionHdl, PayloadReader&)>`

#### `void set_anon_default_payload_handler(OnPayloadCallback callback)`
Sets a default handler for any unhandled opcodes from **anonymous sessions**.
- **Callback signature:** `std::function<void(WsConnectionHdl, Payload)>`

#### `void set_client_identity_handler(IdentityHandler callback)`
Sets a handler that is called when a client authenticates with an Ed25519 identity key during the handshake. The application decides whether to accept or reject the connection.
- `callback`: A function that receives the connection handle and the client's Ed25519 public key. Return `true` to accept, `false` to reject (which disconnects the client).
- **Callback signature:** `std::function<bool(WsConnectionHdl, PublicKey)>`

#### `PublicKey get_client_identity(WsConnectionHdl hdl)`
Returns the verified Ed25519 public key for an authenticated session.
- **Throws:** `LogicError` if the session has no peer identity or is not found.

#### `void send_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Sends an encrypted `Payload` to a specific client identified by their Ed25519 public key.
- `identity_pk`: The client's Ed25519 public key.
- **Throws:** `LogicError` if the identity is not currently connected.

#### `std::future<Payload> async_request_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Sends a request to a specific client identified by their Ed25519 public key and returns a `std::future` for the response. The default timeout from `config_.timeouts.request_ms` applies; on timeout the future resolves with `ObscuraProto::TimeoutError`.
- **Throws:** `LogicError` if the identity is not connected.

#### `Payload sync_request_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Sends a synchronous request to a specific client identified by their Ed25519 public key and waits for the response.
- **Throws:** `LogicError` if the identity is not connected; `ObscuraProto::TimeoutError` if the default timeout (`config_.timeouts.request_ms`) expires before the response arrives.

---

### `class ObscuraProto::net::WsClientWrapper`
A wrapper that runs a WebSocket client to connect to a secure server.

#### `WsClientWrapper(KeyPair server_sign_key)`
Constructor.
- `server_sign_key`: A `KeyPair` containing only the server's public signing key.

#### `void set_client_identity(KeyPair identity_kp)`
Sets the client's Ed25519 identity keypair for authentication. When set, the handshake will include the public key and a signature over the ephemeral key, allowing the server to verify the client's identity.
- `identity_kp`: The client's Ed25519 keypair (public and private).

#### `void connect(const std::string& uri)`
Connects to the server at the given WebSocket URI (e.g., `ws://localhost:9002`) and starts the client thread. The handshake is initiated automatically upon connection.

#### `void disconnect()`
Disconnects from the server.

#### `void send(const Payload& payload)`
Encrypts and sends a `Payload` to the server.

#### `std::future<Payload> async_request(const Payload& payload)`
Sends a `Payload` as a request to the server and returns a `std::future` that will be fulfilled with the server's response. The default timeout from `config_.timeouts.request_ms` (30000 ms) applies; a `0` value in the config means unlimited, and `timeouts.enabled: false` disables the timeout enforcement.
- `payload`: The application-level `Payload` to send as a request.
- **Returns:** A `std::future<Payload>` that will eventually hold the server's application-level response. On timeout the future resolves with `ObscuraProto::TimeoutError` (`get()` rethrows it).
- **Throws:** `LogicError` if the session is not ready.

#### `std::future<Payload> async_request(const Payload& payload, uint32_t timeout_ms)`
Same as `async_request(payload)` but with an explicit per-request timeout.
- `timeout_ms`: Maximum time to wait for the response in milliseconds. `0` = use the default from `config_.timeouts.request_ms`; unlimited = `request_ms: 0` in the config or `timeouts.enabled: false`.
- **Returns:** A `std::future<Payload>` that will eventually hold the server's application-level response. On timeout the future resolves with `ObscuraProto::TimeoutError`.
- **Throws:** `LogicError` if the session is not ready.

#### `Payload sync_request(const Payload& payload)`
Sends a synchronous request to the server and blocks until the response arrives.
- **Throws:** `LogicError` if the session is not ready; `ObscuraProto::TimeoutError` if the default timeout (`config_.timeouts.request_ms`, 30000 ms) expires before the response arrives. A `0` value in the config means unlimited, `timeouts.enabled: false` disables timeout enforcement.

#### `Payload sync_request(const Payload& payload, uint32_t timeout_ms)`
Sends a synchronous request with an explicit per-request timeout and blocks until the response arrives.
- `timeout_ms`: Maximum time to wait for the response in milliseconds. `0` = use the default from `config_.timeouts.request_ms`; unlimited = `request_ms: 0` in the config or `timeouts.enabled: false`.
- **Throws:** `LogicError` if the session is not ready; `ObscuraProto::TimeoutError` if the timeout expires before the response arrives.

#### `void send_response(uint32_t request_id, const Payload& payload)`
Sends a response to the server for a previously received request.
- `request_id`: The unique ID of the request this response is for, extracted from the incoming request payload.
- `payload`: The application-level `Payload` containing the actual response data.

#### `void set_on_ready_callback(OnReadyCallback callback)`
Sets a callback to be invoked when the handshake with the server is successfully completed.
- **Callback signature:** `std::function<void()>`

#### `void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Registers a handler for a specific operation code. When a payload with a matching `op_code` is received from the server, this callback will be invoked.
- `op_code`: The operation code to handle.
- `callback`: The function to call.

#### `void register_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Registers a simplified handler for a request-response interaction with the server. This is the recommended way to handle requests. The library automatically handles reading the request ID and sending the response.
- `op_code`: The operation code of the request to handle.
- `callback`: A function that takes a `PayloadReader&` to read the request parameters and must return a `Payload` object, which will be sent as the response.
- **Callback signature:** `std::function<Payload(PayloadReader&)>`

#### `void set_default_payload_handler(OnPayloadCallback callback)`
Sets a callback function to be invoked when a `Payload` is received from the server and there is no specific handler registered for its `op_code`.
- **Callback signature:** `std::function<void(Payload)>`

#### `void set_on_payload_callback(OnPayloadCallback callback)`
**Deprecated.** This method now calls `set_default_payload_handler`. Use `set_default_payload_handler` for clarity or `register_op_handler` for specific op-codes.

#### `void set_on_disconnect_callback(OnDisconnectCallback callback)`
Sets a callback to be invoked when the client is disconnected from the server.
- **Callback signature:** `std::function<void()>`

---

## `session.hpp`

The main class for managing session state.

### `enum class Role`
Defines the role of the current party.
- `CLIENT`: The session is a client.
- `SERVER`: The session is a server.

### `class ObscuraProto::Session`
Manages the session state, including the handshake and data exchange.

#### `Session(Role role, KeyPair server_sign_key)`
Session constructor.
- `role`: The role of this session (`CLIENT` or `SERVER`).
- `server_sign_key`:
    - For a **server**: the full long-term signing key pair (public and private).
    - For a **client**: a pair containing only the server's public signing key.

- `struct ClientHello`: A message from the client to the server. Contains a list of supported versions and the client's ephemeral public key.
- `struct ServerHello`: A message from the server to the client. Contains the selected version, the server's ephemeral public key, and its signature.

These structures have been moved to `handshake_messages.hpp`.

### Handshake Methods

#### `ClientHello client_initiate_handshake()`
**For the client.** Initiates the handshake. Generates an ephemeral key pair and creates a `ClientHello`.
- **Throws:** `LogicError` if called on the server side.

#### `ServerHello server_respond_to_handshake(const ClientHello& client_hello)`
**For the server.** Processes a `ClientHello`, generates its own ephemeral pair, computes the session keys, and returns a `ServerHello`.
- **Throws:** `LogicError` if called on the client side; `RuntimeError` for version incompatibility or crypto operation failure.

#### `void client_finalize_handshake(const ServerHello& server_hello)`
**For the client.** Finalizes the handshake. Verifies the server's signature and computes the session keys.
- **Throws:** `LogicError` if called before `client_initiate_handshake`; `RuntimeError` for an invalid signature or crypto operation failure.

### Data Exchange Methods

#### `EncryptedPacket encrypt_payload(const Payload& payload)`
Encrypts a `Payload`. Automatically increments the sent message counter.
- **Throws:** `LogicError` if the handshake is not complete.

#### `Payload decrypt_packet(const EncryptedPacket& packet)`
Decrypts an `EncryptedPacket`. Checks the message counter for replay attack protection.
- **Returns:** `Payload` on success.
- **Throws:** `LogicError` if the handshake is not complete; `RuntimeError` on decryption failure or if a replay attack is detected.

### Other Methods

#### `bool is_handshake_complete() const`
Checks if the handshake has been successfully completed.
- **Returns:** `true` if the session is ready for data exchange.

### Client Identity Methods

#### `void set_client_identity_key(KeyPair identity_kp)`
**For the client.** Sets the Ed25519 keypair to be used for client authentication. When set, calls to `client_initiate_handshake()` will include the public key and a signature over the ephemeral X25519 key.
- **Throws:** `LogicError` if called on the server side.

#### `bool has_peer_identity() const`
Checks if the connected peer provided and successfully verified an Ed25519 identity.
- **Returns:** `true` if the peer has a verified identity.

#### `std::optional<PublicKey> get_peer_identity() const`
Returns the verified Ed25519 public key of the connected peer.
- **Returns:** The peer's public key, or `std::nullopt` if no identity was provided.

---

## `stream.hpp`

A bidirectional data stream over an established secure channel. Streams are created by `start_stream` (outgoing) or delivered to an `incoming_stream_handler` (incoming). Inherits from `std::enable_shared_from_this`.

### `class ObscuraProto::Stream`

#### `uint32_t get_stream_id() const`
Returns the unique stream identifier.

#### `std::optional<Payload::OpCode> get_op_code() const`
Returns the application-level opCode the stream was opened with (V1_1), or `std::nullopt` for legacy streams.

#### `void write(const byte_vector& data) noexcept`
Sends a data chunk over the stream. Never throws: if the owning wrapper is destroyed, the data is silently dropped (the internal send callback captures a `std::weak_ptr` to the owner); transport-level send failures are logged and swallowed.

#### `void end() noexcept`
Signals the end of the stream. Never throws; a dead stream is a silent no-op.

#### `void cancel() noexcept`
Immediately terminates the stream from either side. Never throws; a dead stream is a silent no-op.

#### `void set_data_handler(DataHandler handler)`
Sets a callback invoked for each incoming data chunk. Signature: `std::function<void(byte_vector)>`.

#### `void set_end_handler(EndHandler handler)`
Sets a callback invoked when the peer ends the stream. Signature: `std::function<void()>`.

#### `void set_cancel_handler(CancelHandler handler)`
Sets a callback invoked when the stream is cancelled. Signature: `std::function<void()>`.

---

## Protocol Constants

### `constexpr uint16_t RESPONSE_OP_CODE = 0xFFFF`
An internal operation code used by the request-response mechanism to identify a response message. This code is handled internally by the `WsClientWrapper` and `WsServerWrapper` and is not typically exposed to the application logic.
