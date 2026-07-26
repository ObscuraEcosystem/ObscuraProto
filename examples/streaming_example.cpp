#include <chrono>
#include <iostream>
#include <thread>

#include "obscuraproto/crypto.hpp"
#include "obscuraproto/ws_client.hpp"
#include "obscuraproto/ws_server.hpp"

constexpr uint16_t OP_TEXT_STREAM = 0x6001;
constexpr uint16_t OP_BINARY_STREAM = 0x6002;

int main() {
    if (ObscuraProto::Crypto::init() != 0) {
        std::cerr << "Failed to initialize crypto library!" << std::endl;
        return 1;
    }
    std::cout << "Crypto library initialized." << std::endl;

    auto server_long_term_key = ObscuraProto::Crypto::generate_sign_keypair();
    ObscuraProto::KeyPair client_view_of_server_key;
    client_view_of_server_key.publicKey = server_long_term_key.publicKey;

    uint16_t port = 9004;

    // ---- Server ----
    ObscuraProto::net::WsServerWrapper server(server_long_term_key);

    server.register_stream_handler(OP_TEXT_STREAM, [](std::shared_ptr<ObscuraProto::Stream> stream) {
        std::cout << "[SERVER] Dedicated handler for OP_TEXT_STREAM (0x6001). Stream #" << stream->get_stream_id()
                  << std::endl;

        stream->set_data_handler([stream](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            std::cout << "[SERVER] TEXT stream received: \"" << msg << "\"" << std::endl;

            ObscuraProto::byte_vector response = {'E', 'c', 'h', 'o', ':', ' '};
            response.insert(response.end(), data.begin(), data.end());
            stream->write(response);
        });

        stream->set_end_handler([stream]() {
            std::cout << "[SERVER] TEXT stream #" << stream->get_stream_id() << " ended." << std::endl;
            stream->end();
        });

        stream->set_cancel_handler([stream]() {
            std::cout << "[SERVER] TEXT stream #" << stream->get_stream_id() << " canceled." << std::endl;
        });
    });

    server.register_stream_handler(OP_BINARY_STREAM, [](std::shared_ptr<ObscuraProto::Stream> stream) {
        std::cout << "[SERVER] Dedicated handler for OP_BINARY_STREAM (0x6002). Stream #" << stream->get_stream_id()
                  << std::endl;

        stream->set_data_handler([](const ObscuraProto::byte_vector& data) {
            std::cout << "[SERVER] BINARY stream received " << data.size() << " bytes." << std::endl;
        });

        stream->set_end_handler([stream]() {
            std::cout << "[SERVER] BINARY stream #" << stream->get_stream_id() << " ended." << std::endl;
            stream->end();
        });
    });

    server.register_incoming_stream_handler([](std::shared_ptr<ObscuraProto::Stream> stream) {
        std::cout << "[SERVER] Generic fallback handler for stream #" << stream->get_stream_id()
                  << " (no specific handler registered)" << std::endl;
    });

    server.run(port);
    std::cout << "[SERVER] Started on port " << port << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // ---- Client ----
    ObscuraProto::net::WsClientWrapper client(client_view_of_server_key);

    std::promise<void> ready_promise;
    std::future<void> ready_future = ready_promise.get_future();

    client.set_on_ready_callback([&]() {
        std::cout << "[CLIENT] Handshake complete." << std::endl;

        auto text_stream = client.start_stream(OP_TEXT_STREAM);
        std::cout << "[CLIENT] Started TEXT stream #" << text_stream->get_stream_id() << " with opCode 0x" << std::hex
                  << OP_TEXT_STREAM << std::dec << std::endl;

        text_stream->set_data_handler([](const ObscuraProto::byte_vector& data) {
            std::string msg(data.begin(), data.end());
            std::cout << "[CLIENT] TEXT stream received: \"" << msg << "\"" << std::endl;
        });

        text_stream->set_end_handler([text_stream]() {
            std::cout << "[CLIENT] TEXT stream #" << text_stream->get_stream_id() << " closed." << std::endl;
        });

        text_stream->write(ObscuraProto::byte_vector{'H', 'e', 'l', 'l', 'o'});
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        text_stream->write(ObscuraProto::byte_vector{'W', 'o', 'r', 'l', 'd'});
        std::this_thread::sleep_for(std::chrono::milliseconds(50));

        auto binary_stream = client.start_stream(OP_BINARY_STREAM);
        std::cout << "[CLIENT] Started BINARY stream #" << binary_stream->get_stream_id() << " with opCode 0x"
                  << std::hex << OP_BINARY_STREAM << std::dec << std::endl;

        binary_stream->set_end_handler([binary_stream]() {
            std::cout << "[CLIENT] BINARY stream #" << binary_stream->get_stream_id() << " closed." << std::endl;
        });

        ObscuraProto::byte_vector binary_data = {0x00, 0x01, 0x02, 0x03, 0x04};
        binary_stream->write(binary_data);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        binary_stream->end();

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        text_stream->end();

        ready_promise.set_value();
    });

    client.connect("ws://localhost:" + std::to_string(port));
    std::cout << "[CLIENT] Connecting to server..." << std::endl;

    if (ready_future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
        std::cerr << "[CLIENT] Timed out." << std::endl;
        server.stop();
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::cout << "\n[SYSTEM] Shutdown." << std::endl;
    client.disconnect();
    server.stop();

    return 0;
}
