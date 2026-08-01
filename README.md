<p align="center">
  <h1>ObscuraProto</h1>
  <a href="https://github.com/ObscuraEcosystem/ObscuraProto/actions"><img src="https://img.shields.io/github/actions/workflow/status/ObscuraEcosystem/ObscuraProto/ci.yml?style=for-the-badge&logo=github&label=tests&color=8A2BE2" alt="Tests"></a>
  <a href="https://github.com/ObscuraEcosystem/ObscuraProto/stargazers"><img src="https://img.shields.io/github/stars/ObscuraEcosystem/ObscuraProto?style=for-the-badge&logo=githubsponsors&logoColor=FFFFFF&label=stars&color=FFD700" alt="Stars"></a>
  <a href="https://github.com/ObscuraEcosystem/ObscuraProto/issues"><img src="https://img.shields.io/github/issues/ObscuraEcosystem/ObscuraProto?style=for-the-badge&logo=openbugbounty&logoColor=FFFFFF&label=issues&color=FF6B6B" alt="Issues"></a>
  <a href="https://isocpp.org"><img src="https://img.shields.io/badge/C%2B%2B-17%2B-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white" alt="C++17+"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/ObscuraEcosystem/ObscuraProto?style=for-the-badge&logo=libreoffice" alt="LICENSE"></a>
</p>

This document describes the principles of the ObscuraProto **1.0** hybrid encryption protocol. This version uses elliptic curve cryptography and **ChaCha20-Poly1305**.

## 1. Protocol Architecture

The protocol uses a full handshake for secure channel establishment.

### Phase 1: Full Handshake using ECC

This phase is used for the client's first connection to the server and includes protocol version negotiation.

1.  **Client Initiation (Client Hello):**
    *   The client initiates the connection by sending a **list of supported protocol versions** (e.g., `[1.1, 1.0]`).
    *   The client generates its ephemeral ECDH key pair and sends the public part to the server.

2.  **Server Response and Authentication (Server Hello):**
    *   The server receives the list of versions and selects the highest one it also supports. If no common versions are found, the server terminates the connection. All further communication proceeds according to the rules of the selected version.
    *   The server possesses a long-term **Ed25519** key pair. Its public key must be known to the client.
    *   The server generates its ephemeral **ECDH** key pair.
    *   The server signs its public ECDH key with its private **Ed25519** key.
    *   The server sends the client: the **selected protocol version**, its public ECDH key, and the digital signature.

3.  **Client Authentication and Exchange Completion:**
    *   The client verifies that the version selected by the server is in its list of supported versions.
    *   The client verifies the signature of the public ECDH key using the server's public **Ed25519** key.

4.  **Shared Secret Generation:**
    *   The client and server compute a shared secret `S` using the ECDH protocol.
    *   The secret `S` is passed through a **Key Derivation Function (KDF)**, such as HKDF, to generate **two symmetric keys** (one for sending, one for receiving) for the ChaCha20-Poly1305 cipher.

### Phase 2: Data Transfer

1.  Data is encrypted using a modern **AEAD cipher (Authenticated Encryption with Associated Data) ChaCha20-Poly1305**. This cipher combines encryption and authentication in a single operation.
2.  For each message, a unique **Nonce** (number used once) of 12 bytes is generated and transmitted in plaintext.
3.  **Integrity and Authenticity Protection:** The ChaCha20-Poly1305 cipher automatically calculates an **Authentication Tag**. This tag protects against modification and forgery of both the encrypted data and "additional authenticated data" (Associated Data), which in our case is the message counter.
4.  The final message to be sent looks like this: `Nonce + Counter + Ciphertext + Auth Tag`.

## 2. Data Transfer Format

The format is divided into two levels: the **encryption envelope**, which provides security, and the **payload**, which contains the application data itself.

### 2.1. Encryption Envelope Structure

Each message transmitted over a secure channel is wrapped in the following "envelope":

`[Nonce (12 bytes)] + [Counter (8 bytes)] + [Encrypted Data (variable length)] + [Auth Tag (16 bytes)]`

1.  **Nonce (Number used once)**
    *   **Length:** 12 bytes. Generated for each message.
    *   **Purpose:** A unique number for each message, necessary for the correct and secure operation of the ChaCha20 cipher.

2.  **Message Counter**
    *   **Length:** 8 bytes.
    *   **Purpose:** Protection against replay attacks. This field is not encrypted, but its integrity is protected by the authentication tag.

3.  **Encrypted Data (Ciphertext)**
    *   **Content:** The original payload, encrypted using ChaCha20.

4.  **Auth Tag (Authentication Tag)**
    *   **Length:** 16 bytes (for Poly1305).
    *   **Purpose:** Ensures the integrity and authenticity of the `Nonce`, `Counter`, and `Ciphertext`. It is automatically calculated during the encryption process.

### 2.2. Payload Structure

The data placed in the `Encrypted Data` field (before encryption) must have the following binary structure:

`[Operation Code (2 bytes)] + [Operation Parameters (N bytes)]`

*   **Operation Code**: A 2-byte integer (in network byte order, Big-Endian) that uniquely identifies the type of request or message. For example, `0x1001` for an authentication request.
*   **Operation Parameters**: Data required to perform the operation, serialized using the **length-prefix method**.

#### "Length-Prefix" Serialization Method

Each parameter in `Operation Parameters` is encoded using the "length-value" scheme:

`[Field Length (2 bytes)] + [Field Value (N bytes)]`

**Example: Payload for "Login" operation (`0x1001`)**

Suppose the operation requires `username` (string) and `password` (string).
*   `username`: "test" (4 bytes)
*   `password`: "p@ss" (4 bytes)

The final payload before encryption will look like this:

1.  `0x10, 0x01` — Login Operation Code
2.  `0x00, 0x04` — Length of `username`
3.  `0x74, 0x65, 0x73, 0x74` — bytes of "test"
4.  `0x00, 0x04` — Length of `password`
5.  `0x70, 0x40, 0x73, 0x73` — bytes of "p@ss"

This exact sequence of bytes will be encrypted and placed in the `Encrypted Data` field.

### Message Sending Algorithm

1.  **Form the payload:** Assemble the `Operation Code` and `Parameters` into a single byte array according to the binary structure.
2.  **Increment counter:** Increment the value of your sent message counter by 1.
3.  **Generate Nonce:** Create a cryptographically random 12-byte Nonce.
4.  **Encrypt and Authenticate:** Perform the ChaCha20-Poly1305 encryption operation.
    *   **Input:** session key, Nonce, payload (as plaintext), and `Counter` (as "associated data").
    *   **Output:** `ciphertext` and a 16-byte `Auth Tag`.
5.  **Send:** Assemble and send the final message: `Nonce + Counter + ciphertext + Auth Tag`.

### Message Reception and Verification Algorithm

1.  **Split the message:** The received message is divided into `Nonce`, `Counter`, `ciphertext`, and `Auth Tag`.
2.  **Verify and Decrypt:** Perform the ChaCha20-Poly1305 decryption operation.
    *   **Input:** session key, `Nonce`, `ciphertext`, `Auth Tag`, and `Counter` (as "associated data").
    *   This operation automatically verifies the `Auth Tag`. If the tag is invalid, the operation will fail, and the message **must be immediately discarded**.
3.  **Check counter:** If decryption is successful, compare the counter value with the expected one. If it is less than or equal to the last received, discard the message as a replay.
4.  **Parse the payload:**
    *   Read the first 2 bytes of the decrypted data to determine the **Operation Code**.
    *   Depending on the operation code, sequentially parse the remaining data using the length-prefix method to extract all parameters.
5.  **Update counter** and pass the data for processing to the application logic.

This algorithm ensures reliable protection of transmitted data within the ObscuraProto protocol.

## 3. Reliability Analysis

*   **Perfect Forward Secrecy (PFS):** Maintained thanks to ephemeral ECDH keys.
*   **Performance:** ECC provides high speed for asymmetric operations. ChaCha20-Poly1305 is a very fast symmetric cipher.
*   **Trust Model:** The protocol assumes that the client trusts the server's public Ed25519 key in advance.

## 4. Key Decisions

*   **ChaCha20-Poly1305:** A modern, high-performance AEAD cipher that provides both confidentiality and data integrity.
*   **Elliptic Curve Cryptography (ECC):** The basis of asymmetric operations, providing a balance of speed and security, specifically using Ed25519 for signatures and X25519 for key exchange.
*   **Key Derivation Function (KDF):** A critically important component for generating two distinct keys (for sending and receiving) from a shared secret.
*   **Replay Attack Protection:** Implemented using a message counter, which is included in each message and **authenticated using Poly1305**. This prevents the replaying of old messages.

## 5. Basic API Usage

> **Warning:** The following guide describes the low-level "bare metal" API of ObscuraProto. This API is intended for building higher-level abstractions and is not recommended for direct use in most applications, as it requires careful state management.

The library provides a `Session` class that encapsulates the logic for a single client or server connection. The full lifecycle is demonstrated in `examples/basic_encryption_example.cpp`.

### Step 1: Initialization

First, the underlying cryptographic library (libsodium) must be initialized. This must be done once at the start of your application.

```cpp
#include "obscuraproto/crypto.hpp"

if (ObscuraProto::Crypto::init() != 0) {
    // Handle initialization failure
}
```

### Step 2: Key Setup

The server needs a long-term Ed25519 key pair for signing its handshake messages. The client must know the server's public signing key beforehand to verify its identity.

```cpp
// On the server: generate a long-term key
auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

// On the client: configure the server's public key
ObscuraProto::KeyPair client_view_of_server_key;
client_view_of_server_key.publicKey = server_long_term_key.publicKey; // This key must be distributed to the client securely
```

Since v1.1.1 the library also provides deterministic key derivation: `Crypto::keypair_from_seed(seed, len)` builds an Ed25519 key pair from a strictly 32-byte seed, and `Crypto::derive_public_key(private_key, len)` derives the Ed25519 public key from a strictly 64-byte private key. See the [API reference](docs/api_reference.md) for details.

### Step 3: Session Creation

Create `Session` objects for both the client and the server.

```cpp
#include "obscuraproto/session.hpp"

// Server-side
ObscuraProto::Session server_session(ObscuraProto::Role::SERVER, server_long_term_key);

// Client-side
ObscuraProto::Session client_session(ObscuraProto::Role::CLIENT, client_view_of_server_key);
```

### Step 4: Handshake

The handshake is a three-step process involving the exchange of ephemeral keys and signatures.

1.  **Client Initiates:** The client generates an ephemeral key and sends a `ClientHello` message.
    ```cpp
    // Client sends this to the server
    auto client_hello = client_session.client_initiate_handshake();
    ```

2.  **Server Responds:** The server receives the `ClientHello`, verifies it, generates its own ephemeral key, signs it, and computes the shared session keys. It then sends a `ServerHello` back.
    ```cpp
    // Server receives client_hello and sends this back
    auto server_hello = server_session.server_respond_to_handshake(client_hello);
    // The server's handshake is now complete
    assert(server_session.is_handshake_complete());
    ```

3.  **Client Finalizes:** The client receives the `ServerHello`, verifies the server's signature, and computes the same shared session keys.
    ```cpp
    // Client receives server_hello
    client_session.client_finalize_handshake(server_hello);
    // The client's handshake is now complete
    assert(client_session.is_handshake_complete());
    ```
At this point, both parties have a secure channel.

### Step 5: Data Transfer

To send data, you must first construct a `Payload`.

1.  **Create and Encrypt Payload:**
    ```cpp
    #include "obscuraproto/packet.hpp"

    // On the client
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
        .add_param("my_username")
        .add_param("my_secret_password")
        .add_param(1) // Example of adding an integer parameter
        .build();

    // Encrypt the payload to get a packet ready for transport
    ObscuraProto::EncryptedPacket packet_to_send = client_session.encrypt_payload(client_payload);
    ```
    The resulting `packet_to_send` is a `std::vector<uint8_t>` that can be sent over any network transport (TCP, UDP, etc.).

2.  **Receive and Decrypt Packet:**
    ```cpp
    // On the server, after receiving the packet_to_send
    try {
        ObscuraProto::Payload decrypted_payload = server_session.decrypt_packet(packet_to_send);

        // Parse the parameters
        ObscuraProto::PayloadReader reader(decrypted_payload);
        std::string username = reader.read_param<std::string>();
        std::string password = reader.read_param<std::string>();
        int login_attempts = reader.read_param<int>(); // Read the integer parameter
        
        // Use the data...
        std::cout << "Received username: " << username << ", password: " << password << ", attempts: " << login_attempts << std::endl;

    } catch (const ObscuraProto::RuntimeError& e) {
        // Decryption failed (e.g., invalid tag, replay attack)
        // The message must be discarded.
    }
    ```

## 6. High-Level API (WebSocket)

For most use cases, it is recommended to use the high-level WebSocket wrappers, which handle all the complexities of network communication, connection management, and the handshake process automatically.

The full example can be found in `examples/websocket_example.cpp`.

### 6.1. Bidirectional Request-Response Pattern

To simplify common request-response interactions, the high-level API provides dedicated methods for a **fully bidirectional** flow. Both the client and the server can initiate requests and respond to them. The recommended way to handle incoming requests is to use the `register_request_handler` method, which automates response management.

This pattern uses a special internal operation code (`0xFFFF`) for responses and prepends a unique request ID to the payload parameters, but this complexity is hidden from you when using the simplified handlers.

#### Initiating a Request

Both `WsClientWrapper` and `WsServerWrapper` have an `async_request` method. It sends a request and returns a `std::future` that will be fulfilled with the response. There is also a `sync_request` method available for synchronous request-response interactions. Since v1.1.0 both methods accept an optional `timeout_ms` parameter (see [Request Timeouts](#611-request-timeouts) below).

```cpp
// Client-side example
std::future<ObscuraProto::Payload> response_future = client.async_request(request_payload);

// Per-request timeout in milliseconds (0 = use the config default)
std::future<ObscuraProto::Payload> response_future = client.async_request(request_payload, 5000);

// Server-side example (requires a connection handle `hdl`)
std::future<ObscuraProto::Payload> response_future = server.async_request(hdl, request_payload);

// Common logic to get the response
try {
    ObscuraProto::Payload response = response_future.get();
    // Process the application-level response payload.
    // The 0xFFFF wrapper is automatically handled by the library.
} catch (const ObscuraProto::TimeoutError& e) {
    // The response did not arrive within the timeout budget.
}
```

##### 6.1.1. Request Timeouts

Since v1.1.0 every request can be bounded by a timeout:

- `async_request(payload, timeout_ms)` / `sync_request(payload, timeout_ms)` on the client; `async_request(hdl, payload, timeout_ms)` / `sync_request(hdl, payload, timeout_ms)` on the server. The old signatures remain and are fully backward compatible.
- `timeout_ms = 0` means "use the default": `config_.timeouts.request_ms` (30000 ms by default).
- An unlimited request is configured in the config: `request_ms: 0` or `timeouts.enabled: false`.
- `sync_request` waits via `wait_for` and throws `ObscuraProto::TimeoutError` when the timeout expires — it no longer blocks forever.
- For `async_request`, the server's periodic `check_timeouts()` and the client's watchdog complete expired promises with `set_exception(TimeoutError)`; `std::future::get()` rethrows it. The timeout-vs-late-response race is safe: both bookkeeping maps live under a single mutex, so a promise is never completed twice.
- If `send()` fails inside `async_request`, the pending-request state is cleaned up and the future is completed with an exception instead of being left dangling.

#### Handling a Request and Sending a Response (Recommended)

The easiest way to handle a request is to register a specific handler for its operation code using `register_request_handler`. This method takes a callback that receives a `PayloadReader` for the request's parameters and must return a `Payload` object for the response. The library handles the request ID and sends the response automatically.

```cpp
// Server-side example of handling a client's request
server.register_request_handler(0x3001, 
    [](auto hdl, ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
        // 1. Read parameters directly, no need to handle request_id
        std::string client_message = reader.read_param<std::string>();
        
        // 2. Simply return the response payload
        return ObscuraProto::PayloadBuilder(0x3002)
            .add_param("Server got your message: " + client_message)
            .build();
    }
);

// Client-side example of handling a server's request
client.register_request_handler(0x4001, 
    [](ObscuraProto::PayloadReader& reader) -> ObscuraProto::Payload {
        // 1. Read parameters...
        
        // 2. Return the response payload
        return ObscuraProto::PayloadBuilder(0x4002).build();
    }
);
```

For more advanced scenarios where you might not want to respond immediately, you can use `register_op_handler` and manually read the `request_id` and call `send_response`.

A complete example demonstrating this bidirectional pattern can be found in `examples/request_response_example.cpp`.

### 6.2. Connection Lifecycle Callbacks

The high-level API provides callbacks to track the lifecycle of WebSocket connections — when a client connects and when it disconnects. This is useful for logging, connection tracking, and resource management.

Both callbacks receive a `WsConnectionHdl` (connection handle) and are optional — the server functions correctly without them.

#### `set_on_open_callback`

Fires immediately after the WebSocket handshake (TCP connection established), before the ObscuraProto cryptographic handshake begins.

```cpp
server.set_on_open_callback([](WsConnectionHdl hdl) {
    std::cout << "[SERVER] New WebSocket connection" << std::endl;
});
```

#### `set_on_close_callback`

Fires when a WebSocket connection closes, while the handle is still valid. Internal cleanup (session removal, stream cancellation, pending request fulfillment) happens after this callback returns.

```cpp
server.set_on_close_callback([](WsConnectionHdl hdl) {
    std::cout << "[SERVER] Connection closed" << std::endl;
});
```

### Step 1: Initialization and Key Setup

This step is the same as in the low-level API. You need to initialize the crypto library and set up the server's keys.

```cpp
#include "obscuraproto/crypto.hpp"

// Initialize libsodium
ObscuraProto::Crypto::init();

// On the server: generate a long-term key
auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();

// On the client: configure the server's public key
ObscuraProto::KeyPair client_view_of_server_key;
client_view_of_server_key.publicKey = server_long_term_key.publicKey;
```

### Step 2: Running the Server

Create a `WsServerWrapper`, set callbacks to handle incoming data, and run it on a port. You can register handlers for specific `op_code`s or a default handler for any unhandled messages.

```cpp
#include "obscuraproto/ws_server.hpp"

// Create the server
ObscuraProto::net::WsServerWrapper server(server_long_term_key);

// Set a default handler for any non-request payloads
server.set_default_payload_handler([&server](auto hdl, ObscuraProto::Payload payload) {
    std::cout << "[SERVER] Received a payload with op_code 0x" << std::hex << payload.op_code << std::dec << std::endl;
    
    // Example of reading mixed parameters
    ObscuraProto::PayloadReader reader(payload);
    std::string username = reader.read_param<std::string>();
    std::string password = reader.read_param<std::string>();
    uint32_t login_attempts = reader.read_param<uint32_t>();
    std::cout << "[SERVER] Decrypted: User=" << username << ", Pass=" << password << ", Attempts=" << login_attempts << std::endl;

    // Create and send a response (as a simple push message)
    ObscuraProto::Payload response_payload = ObscuraProto::PayloadBuilder(0x2002)
        .add_param("Hello from server!")
        .build();
    server.send(hdl, response_payload);
});

// Run the server on port 9002
server.run(9002);
```

### Step 3: Running the Client

Create a `WsClientWrapper`, set callbacks for events, and connect to the server.

```cpp
#include "obscuraproto/ws_client.hpp"

// Create the client
ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);

// Set a callback for when the secure channel is ready
client.set_on_ready_callback([&client]() {
    std::cout << "[CLIENT] Handshake complete. Sending a message..." << std::endl;
    ObscuraProto::Payload client_payload = ObscuraProto::PayloadBuilder(0x1001)
        .add_param("my_username")
        .add_param("my_password")
        .add_param(1)
        .build();
    client.send(client_payload);
});

// Register a handler for a specific op_code from the server
client.register_op_handler(0x2002, [](ObscuraProto::Payload payload) {
    std::cout << "[CLIENT] Received a response from the server." << std::endl;
    ObscuraProto::PayloadReader reader(payload);
    std::string message = reader.read_param<std::string>();
    std::cout << "[CLIENT] Decrypted response: " << message << std::endl;
});

// Connect to the server
client.connect("ws://localhost:9002");

// ... wait for work to be done ...

// Disconnect when finished
client.disconnect();
server.stop();
```

## 7. Client Identity Authentication

ObscuraProto supports **optional client authentication** at the protocol level using Ed25519 digital signatures. This allows the server to verify which client is connecting and to send messages directly to a specific client by their public key.

### 7.1. How It Works

During the handshake, the client can include its Ed25519 public key and a signature over its ephemeral X25519 key. The server verifies the signature and, if valid, associates the connection with that public key.

*   **Without identity (`has_client_identity=false`):** The session is **anonymous**. It falls into a separate handler namespace (`register_anon_*`), intended for registration, login, or other pre-authentication flows.
*   **With identity (`has_client_identity=true`):** The client proves ownership of an Ed25519 private key. The server calls the `client_identity_handler` callback, letting the application accept or reject the connection. On acceptance, the session is fully authenticated and addressable by its public key.

### 7.2. Anonymous Sessions

Anonymous connections live in a completely separate namespace from authenticated ones. They have their own handler registrations:

```cpp
// Register handlers for anonymous sessions only
server.register_anon_op_handler(REGISTER_OP, [](auto hdl, Payload payload) { ... });
server.register_anon_request_handler(REGISTER_REQ, [](auto hdl, PayloadReader& r) -> Payload { ... });
server.set_anon_default_payload_handler([](auto hdl, Payload payload) { ... });

// Send to an anonymous client
server.send_anonymous(hdl, payload);
```

This allows you to expose only specific operations (like registration) to anonymous users while keeping the rest of your application behind authentication.

### 7.3. Setting Up Client Identity

**Client side:** Generate (or load) an Ed25519 keypair and pass it to the client wrapper before connecting.

```cpp
ObscuraProto::net::WsClientWrapper client(server_public_key);
client.set_client_identity(client_device_key);  // Ed25519 keypair
client.connect("ws://localhost:9002");
```

**Server side:** Register an identity handler that validates the client's public key (e.g., check it exists in a database).

```cpp
server.set_client_identity_handler(
    [](WsConnectionHdl hdl, ObscuraProto::PublicKey pk) -> bool {
        // Return true to accept, false to reject
        return user_database.is_key_registered(pk);
    }
);
```

### 7.4. Addressing Clients by Identity

Once authenticated, you can send messages directly to a client by their public key. The server maintains an internal mapping of `PublicKey -> ConnectionHandle`.

```cpp
// Send a payload to a specific client
server.send_to_identity(client_pk, payload);

// Send a request and wait for response
auto response = server.sync_request_to_identity(client_pk, request);
```

This enables server-to-client push notifications and targeted request-response without tracking raw connection handles.

### 7.5. Complete Example

Full working code is in `examples/client_identity_example.cpp`. The flow:

1. **Anonymous** connection: client registers its Ed25519 public key with the server (via `anon_request_handler`).
2. **Authenticated** connection: client connects again, this time with `set_client_identity()`. The handshake includes the public key + signature.
3. Server verifies the signature, calls `client_identity_handler`, accepts the connection.
4. Server sends a message to the client using `send_to_identity(client_pk, ...)`.

### 7.6. Security Notes

* Ed25519 keys are 256 bits, satisfying the protection requirement.
* The signature proves the client possesses the corresponding private key **at the time of the handshake**, preventing impersonation.
* Application-level key management (registration, storage, device-specific key generation, hardware binding) is entirely the responsibility of the application.
* Anonymous sessions share the same encryption strength — they are not "less secure", just unauthorised.

---

## 8. Bidirectional Streaming

To support real-time applications like voice/video calls or AI responses, ObscuraProto includes a high-performance, bidirectional streaming system. It operates over the same secure channel, allowing simultaneous streaming and request-response messaging or packet sending.

*   **Encrypted & Concurrent:** All stream data is automatically encrypted and authenticated using the established session keys. The system is designed to not block other communication.
*   **Bidirectional:** Both the client and server can initiate streams to the other party. For a call, each side would start its own outgoing stream.
*   **High-Throughput:** Data is sent in efficient chunks. The underlying WebSocket ensures ordered and reliable delivery, minimizing overhead.

### 8.1. Stream Lifecycle and Payload Structure

A stream is managed by a unique `stream_id` and a set of special operation codes. The actual stream data (e.g., a video frame) is sent as a parameter within a `STREAM_DATA` payload.

*   `stream_id`: A `uint32_t` that identifies a specific stream.

The payload for a `STREAM_DATA` message looks like this before encryption:
`[OpCode (2)] + [stream_id (4)] + [data_chunk (N)]`

#### Exception Contract

`Stream::write`, `Stream::end` and `Stream::cancel` are `noexcept` — they never throw. The internal send callback captures a `std::weak_ptr` to the owning wrapper: once the owner is destroyed the callback is a silent no-op, and transport-level send failures are logged and swallowed by the wrapper. Data written to a dead stream is dropped.

### 8.3. Streaming API Usage Example

The API is designed around two main concepts: `register_incoming_stream_handler` to receive new streams and `start_stream` to initiate one.

#### Server-side: Accepting an incoming stream

The server registers a handler that will be invoked when a client starts a new stream.

```cpp
// Server-side
server.register_incoming_stream_handler(
    [&server](std::shared_ptr<ObscuraProto::net::IncomingStream> stream) {
        std::cout << "[SERVER] New incoming stream #" << stream->get_stream_id() << std::endl;

        // Set a handler for incoming data chunks
        stream->set_data_handler([](const ObscuraProto::byte_vector& data) {
            std::cout << "[SERVER] Received " << data.size() << " bytes for stream." << std::endl;
            // Process the video/audio chunk...
        });

        // Set a handler for the end of the stream
        stream->set_end_handler([&server, stream]() {
            std::cout << "[SERVER] Stream #" << stream->get_stream_id() << " ended." << std::endl;
        });

        // Set a handler for stream cancellation
        stream->set_cancel_handler([stream]() {
            std::cout << "[SERVER] Stream #" << stream->get_stream_id() << " was canceled." << std::endl;
        });
    }
);
```

#### Client-side: Initiating a stream and sending data

The client calls `start_stream` to get an `OutgoingStream` object and then uses it to send data.

```cpp
// Client-side, after connection is ready (in on_ready_callback)
auto outgoing_stream = client.start_stream();
std::cout << "[CLIENT] Started outgoing stream #" << outgoing_stream->get_stream_id() << std::endl;

// Simulate sending video frames every 100ms
for (int i = 0; i < 5; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    ObscuraProto::byte_vector video_chunk = {'f','a','k','e','_','d','a','t','a'};
    std::cout << "[CLIENT] Sending chunk " << i << " for stream #" << outgoing_stream->get_stream_id() << std::endl;
    outgoing_stream->write(video_chunk);
}

// Signal that we are done sending data
std::cout << "[CLIENT] Ending stream #" << outgoing_stream->get_stream_id() << std::endl;
outgoing_stream->end();
```


### 8.2. System Operation Codes

The following `OpCode`s are reserved for the internal mechanics of the ObscuraProto library. You should **not** use them for your own application logic.

Each stream is **bidirectional**: both sides can write and read data using the same `Stream` object.

| OpCode (Hex)    | Name                  | Description                                                 |
| --------------- | --------------------- | ----------------------------------------------------------- |
| `0xFFFF`        | `RESPONSE`            | Internal code for handling responses to `async_request`.    |
| `0xFFFD`        | `STREAM_START`        | Initiates a new data stream.                                |
| `0xFFFC`        | `STREAM_DATA`         | A chunk of data belonging to an existing stream.            |
| `0xFFFB`        | `STREAM_END`          | Signals that the sender has finished writing to the stream. |
| `0xFFFA`        | `STREAM_CANCEL`       | Immediately terminates a stream from either side.           |


### Dependencies

All dependencies (**libsodium**, **websocketpp**, **asio**) are fetched and configured automatically via CMake's `FetchContent`. You only need to link against the `obscuraproto` target.

```cmake
target_link_libraries(your_executable_name
    PRIVATE
        obscuraproto
)
```

## 9. Configuration

Starting from v1.0, ObscuraProto supports a YAML-based configuration system. All server-side protections (rate limiting, connection limits, message limits, timeouts) and reserved opcodes are defined in the config.

Default values are hardcoded — you only need a config file if you want to override them.

### 9.1. Loading a Config

```cpp
ObscuraProto::Config cfg = ObscuraProto::Config::from_yaml("config.yml");
ObscuraProto::net::WsServerWrapper server(server_key, cfg);
```

If the file is not found, defaults are used and a warning is printed. Load the config **once at startup** — it is immutable after creation.

### 9.2. Config Reference

See `config.yml` in the project root for the full reference with comments.

| Section              | Key                         | Default    | Description                                |
| -------------------- | --------------------------- | ---------- | ------------------------------------------ |
| `rate_limiting`      | `enabled`                   | `true`     | Enable/disable all rate limiting           |
|                      | `messages_per_second`       | `100`      | Max messages/sec per connection (`0`=unlim)|
|                      | `burst_size`                | `200`      | Token bucket burst size (`0`=same as rate) |
|                      | `handshake_attempts_per_minute` | `10`   | Max handshake attempts/min per IP          |
|                      | `connections_per_minute`    | `30`       | Max new connections/min per IP             |
| `connection_limits`  | `enabled`                   | `true`     | Enable/disable connection limits           |
|                      | `max_per_ip`                | `10`       | Max concurrent connections per IP          |
|                      | `max_total`                 | `1000`     | Max total concurrent connections           |
| `message_limits`     | `enabled`                   | `true`     | Enable/disable message size limits         |
|                      | `max_ws_frame_size`         | `1048576`  | Max raw WebSocket frame (bytes)            |
|                      | `max_decrypted_payload`     | `65535`    | Max decrypted payload params (bytes)       |
| `timeouts`           | `enabled`                   | `true`     | Enable/disable all timeouts                |
|                      | `handshake_ms`              | `10000`    | Handshake timeout (ms)                     |
|                      | `idle_ms`                   | `300000`   | Idle connection timeout (ms)               |
|                      | `check_interval_ms`         | `5000`     | Timeout check interval (ms)                |
|                      | `request_ms`                | `30000`    | Default request timeout (ms; `0` = unlimited) |
| `opcodes`            | `RESPONSE`                  | `0xFFFF`   | Reserved: response opcode                  |
|                      | `STREAM_START`              | `0xFFFD`   | Reserved: stream start opcode              |
|                      | `STREAM_DATA`               | `0xFFFC`   | Reserved: stream data opcode               |
|                      | `STREAM_END`                | `0xFFFB`   | Reserved: stream end opcode                |
|                      | `STREAM_CANCEL`             | `0xFFFA`   | Reserved: stream cancel opcode             |

### 9.3. Using the Config Without a File

You can also create and modify a `Config` object programmatically:

```cpp
ObscuraProto::Config cfg = ObscuraProto::Config::with_defaults();
cfg.rate_limit.messages_per_second = 500;
cfg.timeouts.handshake_ms = 15000;
cfg.opcodes.RESPONSE = 0xE0E0;

ObscuraProto::net::WsServerWrapper server(server_key, cfg);
```

### 9.4. Notable Changes in v1.0

- **Rate Limiting** — per-connection token bucket, per-IP sliding windows
- **Connection Limits** — max connections per IP and total
- **Message Size Limits** — configurable WebSocket frame and decrypted payload limits
- **Timeouts** — handshake and idle timeouts with periodic checking
- **Secure Memory** — private keys are allocated via `sodium_malloc` and zeroed on destruction
- **Configurable OpCodes** — reserved opcodes can be changed in the config if they conflict with application opcodes
- Session resumption (Phase 2) has been **removed** from the protocol and documentation. It may be re-introduced in a future version.
