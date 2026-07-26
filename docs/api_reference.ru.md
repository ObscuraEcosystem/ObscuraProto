# Справочник по API ObscuraProto

Этот документ предоставляет детальное описание каждого публичного компонента библиотеки ObscuraProto.

---

## `errors.hpp`

Определяет иерархию исключений, используемых в библиотеке.

### `class ObscuraProto::Exception`
Базовый класс для всех исключений библиотеки. Наследуется от `std::exception`.

#### `virtual const char* what() const noexcept override`
Возвращает сообщение об ошибке.

---

### `class ObscuraProto::RuntimeError`
Исключение, выбрасываемое при ошибках времени выполнения.
- **Примеры:** сбой расшифровки, неверная подпись, ошибка обмена ключами.

---

### `class ObscuraProto::LogicError`
Исключение, указывающее на некорректное использование API.
- **Примеры:** попытка зашифровать данные до завершения рукопожатия, вызов метода, предназначенного только для сервера, на стороне клиента.

---

### `class ObscuraProto::InvalidArgument`
Исключение, выбрасываемое при передаче некорректных аргументов в функцию. Наследуется от `LogicError`.
- **Примеры:** передача ключа неверного размера.

---

## `keys.hpp`

Определяет базовые структуры для хранения криптографических ключей и подписей.

### `struct ObscuraProto::PublicKey`
Представляет публичный ключ.
- `std::vector<uint8_t> data`: Сырые байты ключа.
- `bool operator==(const PublicKey& other) const`: Сравнивает два публичных ключа по их данным.
- `bool operator!=(const PublicKey& other) const`: Сравнение на неравенство.
- `bool operator<(const PublicKey& other) const`: Лексикографическое сравнение данных ключа (для использования в `std::map`).

### `struct ObscuraProto::PrivateKey`
Представляет приватный ключ.
- `std::vector<uint8_t> data`: Сырые байты ключа.

### `struct ObscuraProto::KeyPair`
Представляет пару, состоящую из публичного и приватного ключей.
- `PublicKey publicKey`: Публичный ключ.
- `PrivateKey privateKey`: Приватный ключ.

### `struct ObscuraProto::Signature`
Представляет цифровую подпись.
- `std::vector<uint8_t> data`: Сырые байты подписи.

---

## `version.hpp`

Определяет константы и типы для управления версией протокола.

### `using Version = uint16_t`
Псевдоним для типа версии протокола. Версия `1.0` представляется как `0x0100`.

### `const std::vector<Version> SUPPORTED_VERSIONS`
Список версий протокола, поддерживаемых текущей версией библиотеки.

---

## `packet.hpp`

Определяет структуру полезной нагрузки до шифрования и после расшифровки, а также предоставляет вспомогательные классы для построения и парсинга полезных нагрузок.

### `using byte_vector = std::vector<uint8_t>`
Псевдоним для представления массива байт.

### `using EncryptedPacket = byte_vector`
Псевдоним для зашифрованного пакета. Его содержимое непрозрачно и готово к передаче по сети.

### `class ObscuraProto::Payload`
Класс, который содержит код операции и сериализованные параметры.

- `OpCode op_code`: 16-битный код операции, определяющий тип сообщения.
- `byte_vector parameters`: Сериализованные параметры для данной операции.

#### `byte_vector serialize() const`
Сериализует весь объект `Payload` (код операции + параметры) в единый массив байт, готовый к шифрованию.

#### `static Payload deserialize(const byte_vector& data)`
Десериализует массив байт обратно в объект `Payload`.
- **Выбрасывает:** `RuntimeError`, если данные повреждены или их размер недостаточен.

---

### `class ObscuraProto::PayloadBuilder`
Вспомогательный класс для удобного конструирования объектов `Payload` с различными параметрами.

#### `explicit PayloadBuilder(Payload::OpCode op_code)`
Конструктор. Инициализирует построитель указанным кодом операции.

#### `PayloadBuilder& add_param(const T& param)`
Добавляет параметр заданного типа. Библиотека имеет перегрузки для `std::string`, `byte_vector`, `bool`, `float`, `double` и всех стандартных целочисленных типов (`int8_t`, `uint8_t`, `int16_t`, `uint16_t` и т.д.). Все параметры сериализуются с использованием метода с префиксом длины.
- **Возвращает:** Ссылку на построитель для цепочки вызовов методов.
- **Выбрасывает:** `RuntimeError`, если размер строкового параметра или `byte_vector` превышает `UINT16_MAX`.

#### `Payload build()`
Завершает конструирование и возвращает объект `Payload`.

---

### `class ObscuraProto::PayloadReader`
Вспомогательный класс для последовательного извлечения параметров из полученного `Payload`.

#### `explicit PayloadReader(const Payload& payload)`
Конструктор. Инициализирует считыватель полем `parameters` из объекта `Payload`.

#### `template<typename T> T read_param()`
Извлекает следующий параметр и приводит его к указанному шаблонному типу `T`. Метод поддерживает `std::string`, `byte_vector`, `bool`, `float`, `double` и все стандартные целочисленные типы.
- **Пример:** `std::string name = reader.read_param<std::string>();`, `int score = reader.read_param<int32_t>();`
- **Возвращает:** Параметр, приведенный к типу `T`.
- **Выбрасывает:** `RuntimeError`, если данные некорректны, недостаточны или если размер сохраненного параметра не соответствует размеру запрошенного типа `T`.

#### `bool has_more() const`
Проверяет, есть ли еще параметры для чтения в полезной нагрузке.
- **Возвращает:** `true`, если есть непрочитанные параметры, иначе `false`.

---

## `crypto.hpp`

Статический класс, предоставляющий все низкоуровневые криптографические функции.

### `static int init()`
Инициализирует криптографическую библиотеку (libsodium). **Должна быть вызвана один раз** при запуске приложения.
- **Возвращает:** `0` в случае успеха, `-1` при ошибке.

### `static KeyPair generate_kx_keypair()`
Генерирует пару ключей (X25519) для обмена ключами по алгоритму Диффи-Хеллмана (ECDH).

### `static KeyPair generate_sign_keypair()`
Генерирует пару ключей (Ed25519) для создания и проверки цифровых подписей.

### `static Signature sign(const byte_vector& message, const PrivateKey& private_key)`
Создает цифровую подпись для сообщения.
- **Выбрасывает:** `InvalidArgument`, если размер приватного ключа некорректен.

### `static bool verify(const Signature& signature, const byte_vector& message, const PublicKey& public_key)`
Проверяет цифровую подпись.
- **Возвращает:** `true`, если подпись верна, иначе `false`.

### `struct SessionKeys`
Структура для хранения сессионных ключей, полученных после рукопожатия.
- `byte_vector rx`: Ключ для расшифровки входящих сообщений.
- `byte_vector tx`: Ключ для зашифровки исходящих сообщений.

### `static SessionKeys client_compute_session_keys(...)`
**Для клиента.** Вычисляет сессионные ключи на основе своей эфемерной пары ключей и публичного эфемерного ключа сервера.
- **Выбрасывает:** `InvalidArgument` при неверных размерах ключей, `RuntimeError` при сбое вычислений.

### `static SessionKeys server_compute_session_keys(...)`
**Для сервера.** Вычисляет сессионные ключи на основе своей эфемерной пары ключей и публичного эфемерного ключа клиента.
- **Выбрасывает:** `InvalidArgument` при неверных размерах ключей, `RuntimeError` при сбое вычислений.

### `static EncryptedPacket encrypt(const Payload& payload, uint64_t counter, const byte_vector& key)`
Шифрует `Payload` с использованием ChaCha20-Poly1305.
- `counter`: Счётчик сообщений для защиты от replay-атак. Он включается в пакет как ассоциированные данные (не шифруется, но защищается аутентификационным тегом).
- **Возвращает:** `EncryptedPacket` в формате `[Nonce][Counter][Ciphertext+Tag]`.
- **Выбрасывает:** `InvalidArgument` при неверном размере ключа.

### `struct DecryptedResult`
Результат успешной расшифровки.
- `Payload payload`: Расшифрованная полезная нагрузка.
- `uint64_t counter`: Счётчик, извлечённый из пакета.

### `static DecryptedResult decrypt(const EncryptedPacket& packet, const byte_vector& key)`
Расшифровывает пакет. Проверяет аутентификационный тег.
- **Возвращает:** `DecryptedResult` в случае успеха.
- **Выбрасывает:** `InvalidArgument` при неверном размере ключа, `RuntimeError` при сбое расшифровки (неверный тег, поврежденные данные).

---

## `handshake_messages.hpp`

Определяет структуры, используемые на этапе рукопожатия.

### `struct ObscuraProto::ClientHello`
Представляет начальное сообщение, отправляемое клиентом.
- `std::vector<Version> supported_versions`: Список версий протокола, которые поддерживает клиент.
- `PublicKey ephemeral_pk`: Эфемерный публичный ключ клиента для данной сессии.
- `bool has_client_identity`: Указывает, включил ли клиент ключ идентификации Ed25519 и подпись.
- `PublicKey identity_pk`: Публичный ключ Ed25519 клиента (действителен только если `has_client_identity` равен `true`).
- `Signature identity_sig`: Подпись Ed25519 над `ephemeral_pk.data` (действительна только если `has_client_identity` равен `true`).

#### `byte_vector serialize() const`
Сериализует объект `ClientHello` в байтовый вектор для передачи по сети.

#### `static ClientHello deserialize(const byte_vector& data)`
Десериализует байтовый вектор обратно в объект `ClientHello`.
- **Выбрасывает:** `RuntimeError`, если данные повреждены или их размер недостаточен.

---

### `struct ObscuraProto::ServerHello`
Представляет ответ сервера на `ClientHello`.
- `Version selected_version`: Версия протокола, выбранная сервером.
- `PublicKey ephemeral_pk`: Эфемерный публичный ключ сервера для данной сессии.
- `Signature signature`: Подпись сервера под своим эфемерным публичным ключом для аутентификации.

#### `byte_vector serialize() const`
Сериализует объект `ServerHello` в байтовый вектор для передачи по сети.

#### `static ServerHello deserialize(const byte_vector& data)`
Десериализует байтовый вектор обратно в объект `ServerHello`.
- **Выбрасывает:** `RuntimeError`, если данные повреждены или их размер недостаточен.

---

## Сетевые обертки (`ws_client.hpp`, `ws_server.hpp`)

Эти файлы предоставляют высокоуровневые обертки для запуска протокола ObscuraProto поверх WebSocket. Это рекомендуемый API для большинства сценариев использования.

### `namespace ObscuraProto::net`
Содержит все классы, связанные с работой по сети.

---

### `class ObscuraProto::net::WsServerWrapper`
Класс-обертка, который запускает WebSocket-сервер для обработки множества защищенных клиентских подключений.

#### `WsServerWrapper(KeyPair server_sign_key)`
Конструктор.
- `server_sign_key`: Долгосрочная пара ключей подписи сервера (публичный и приватный).

#### `void run(uint16_t port)`
Запускает сервер в новом потоке, который слушает подключения на указанном порту.

#### `void stop()`
Останавливает сервер и отключает всех клиентов.

#### `void send(WsConnectionHdl hdl, const Payload& payload)`
Шифрует и отправляет `Payload` определенному клиенту, идентифицированному по его дескриптору соединения `hdl`.

#### `void send_response(WsConnectionHdl hdl, uint32_t request_id, const Payload& payload)`
Отправляет ответ клиенту на ранее полученный запрос. `payload` здесь — это полезная нагрузка ответа на уровне приложения. Библиотека автоматически оборачивает ее внутренним `RESPONSE_OP_CODE` (`0xFFFF`) и `request_id`.
- `hdl`: Дескриптор соединения клиента, которому отправляется ответ.
- `request_id`: Уникальный ID запроса, для которого предназначен этот ответ, извлеченный из входящей полезной нагрузки запроса.
- `payload`: `Payload` на уровне приложения, содержащий фактические данные ответа.

#### `std::future<Payload> async_request(WsConnectionHdl hdl, const Payload& payload)`
Отправляет `Payload` в качестве запроса определенному клиенту и возвращает `std::future`, который будет выполнен с ответом клиента.
- `hdl`: Дескриптор соединения клиента, которому отправляется запрос.
- `payload`: `Payload` на уровне приложения для отправки в качестве запроса.
- **Возвращает:** `std::future<Payload>`, который в конечном итоге будет содержать ответ клиента на уровне приложения.
- **Выбрасывает:** `LogicError`, если сессия не готова.

#### `void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Регистрирует обработчик для конкретного кода операции. Когда будет получена полезная нагрузка с соответствующим `op_code`, будет вызван этот колбэк.
- `op_code`: Код операции для обработки.
- `callback`: Функция для вызова.

#### `void register_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Регистрирует упрощенный обработчик для взаимодействия "запрос-ответ". Это рекомендуемый способ обработки запросов. Библиотека автоматически обрабатывает чтение ID запроса и отправку ответа.
- `op_code`: Код операции запроса для обработки.
- `callback`: Функция, которая принимает `PayloadReader&` для чтения параметров запроса и должна вернуть объект `Payload`, который будет отправлен в качестве ответа.
- **Сигнатура:** `std::function<Payload(WsConnectionHdl, PayloadReader&)>`

#### `void set_default_payload_handler(OnPayloadCallback callback)`
Устанавливает функцию обратного вызова, которая будет вызвана при получении `Payload` от любого клиента, если для его `op_code` не зарегистрирован специальный обработчик. Работает как "catch-all" обработчик.
- **Сигнатура:** `std::function<void(WsConnectionHdl, Payload)>`

#### `void set_on_open_callback(OnOpenCallback callback)`
Регистрирует колбэк, вызываемый при установлении нового WebSocket-соединения. Колбэк срабатывает сразу после TCP/WebSocket рукопожатия, до криптографического рукопожатия ObscuraProto.
- `callback`: Функция, принимающая дескриптор соединения нового клиента.
- **Сигнатура:** `std::function<void(WsConnectionHdl)>`

#### `void set_on_close_callback(OnCloseCallback callback)`
Регистрирует колбэк, вызываемый при закрытии WebSocket-соединения. Колбэк срабатывает, пока дескриптор соединения ещё валиден, до очистки сессий, потоков и ожидающих запросов.
- `callback`: Функция, принимающая дескриптор соединения отключившегося клиента.
- **Сигнатура:** `std::function<void(WsConnectionHdl)>`

#### `void set_on_payload_callback(OnPayloadCallback callback)`
**Устарело.** Этот метод теперь вызывает `set_default_payload_handler`. Используйте `set_default_payload_handler` для ясности или `register_op_handler` для конкретных кодов операций.

#### `void send_anonymous(WsConnectionHdl hdl, const Payload& payload)`
Шифрует и отправляет `Payload` анонимному клиенту (подключившемуся без аутентификации).
- **Выбрасывает:** `LogicError`, если анонимная сессия не готова.

#### `void register_anon_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Регистрирует обработчик для конкретного кода операции от **анонимных сессий**.
- `op_code`: Код операции для обработки.
- `callback`: Функция для вызова. Сигнатура: `void(WsConnectionHdl, Payload)`.

#### `void register_anon_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Регистрирует упрощенный обработчик запрос-ответ для **анонимных сессий**. Библиотека автоматически управляет чтением ID запроса и отправкой ответа.
- `op_code`: Код операции запроса для обработки.
- `callback`: Функция, принимающая `PayloadReader&` для чтения параметров запроса и возвращающая `Payload`.
- **Сигнатура:** `std::function<Payload(WsConnectionHdl, PayloadReader&)>`

#### `void set_anon_default_payload_handler(OnPayloadCallback callback)`
Устанавливает обработчик по умолчанию для любых необработанных кодов операций от **анонимных сессий**.
- **Сигнатура:** `std::function<void(WsConnectionHdl, Payload)>`

#### `void set_client_identity_handler(IdentityHandler callback)`
Устанавливает обработчик, вызываемый, когда клиент аутентифицируется с ключом Ed25519 во время рукопожатия. Приложение решает, принять или отклонить соединение.
- `callback`: Функция, получающая дескриптор соединения и публичный ключ Ed25519 клиента. Верните `true` для принятия, `false` для отклонения (отключает клиента).
- **Сигнатура:** `std::function<bool(WsConnectionHdl, PublicKey)>`

#### `PublicKey get_client_identity(WsConnectionHdl hdl)`
Возвращает проверенный публичный ключ Ed25519 для аутентифицированной сессии.
- **Выбрасывает:** `LogicError`, если сессия не имеет идентификации или не найдена.

#### `void send_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Отправляет зашифрованный `Payload` конкретному клиенту, идентифицированному по его публичному ключу Ed25519.
- **Выбрасывает:** `LogicError`, если идентификация в данный момент не подключена.

#### `std::future<Payload> async_request_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Отправляет запрос конкретному клиенту по его публичному ключу Ed25519 и возвращает `std::future` для ответа.
- **Выбрасывает:** `LogicError`, если идентификация не подключена.

#### `Payload sync_request_to_identity(const PublicKey& identity_pk, const Payload& payload)`
Отправляет синхронный запрос конкретному клиенту по его публичному ключу Ed25519 и ожидает ответа.
- **Выбрасывает:** `LogicError`, если идентификация не подключена.

---

### `class ObscuraProto::net::WsClientWrapper`
Класс-обертка, который запускает WebSocket-клиент для подключения к защищенному серверу.

#### `WsClientWrapper(KeyPair server_sign_key)`
Конструктор.
- `server_sign_key`: `KeyPair`, содержащий только публичный ключ подписи сервера.

#### `void set_client_identity(KeyPair identity_kp)`
Устанавливает пару ключей Ed25519 для аутентификации клиента. При установке рукопожатие будет включать публичный ключ и подпись эфемерного ключа, что позволит серверу проверить личность клиента.
- `identity_kp`: Пара ключей Ed25519 клиента (публичный и приватный).

#### `void connect(const std::string& uri)`
Подключается к серверу по указанному WebSocket URI (например, `ws://localhost:9002`) и запускает клиентский поток. Рукопожатие инициируется автоматически при подключении.

#### `void disconnect()`
Отключается от сервера.

#### `void send(const Payload& payload)`
Шифрует и отправляет `Payload` на сервер.

#### `std::future<Payload> async_request(const Payload& payload)`
Отправляет `Payload` в качестве запроса на сервер и возвращает `std::future`, который будет выполнен с ответом сервера.
- `payload`: `Payload` на уровне приложения для отправки в качестве запроса.
- **Возвращает:** `std::future<Payload>`, который в конечном итоге будет содержать ответ сервера на уровне приложения.
- **Выбрасывает:** `LogicError`, если сессия не готова.

#### `void send_response(uint32_t request_id, const Payload& payload)`
Отправляет ответ на сервер для ранее полученного запроса.
- `request_id`: Уникальный ID запроса, для которого предназначен этот ответ, извлеченный из входящей полезной нагрузки запроса.
- `payload`: `Payload` на уровне приложения, содержащий фактические данные ответа.

#### `void set_on_ready_callback(OnReadyCallback callback)`
Устанавливает функцию обратного вызова, которая будет вызвана после успешного завершения рукопожатия с сервером.
- **Сигнатура:** `std::function<void()>`

#### `void register_op_handler(Payload::OpCode op_code, OnPayloadCallback callback)`
Регистрирует обработчик для конкретного кода операции. Когда от сервера будет получена полезная нагрузка с соответствующим `op_code`, будет вызван этот колбэк.
- `op_code`: Код операции для обработки.
- `callback`: Функция для вызова.

#### `void register_request_handler(Payload::OpCode op_code, OnRequestCallback callback)`
Регистрирует упрощенный обработчик для взаимодействия "запрос-ответ" с сервером. Это рекомендуемый способ обработки запросов. Библиотека автоматически обрабатывает чтение ID запроса и отправку ответа.
- `op_code`: Код операции запроса для обработки.
- `callback`: Функция, которая принимает `PayloadReader&` для чтения параметров запроса и должна вернуть объект `Payload`, который будет отправлен в качестве ответа.
- **Сигнатура:** `std::function<Payload(PayloadReader&)>`

#### `void set_default_payload_handler(OnPayloadCallback callback)`
Устанавливает функцию обратного вызова, которая будет вызвана при получении `Payload` от сервера, если для его `op_code` не зарегистрирован специальный обработчик.
- **Сигнатура:** `std::function<void(Payload)>`

#### `void set_on_payload_callback(OnPayloadCallback callback)`
**Устарело.** Этот метод теперь вызывает `set_default_payload_handler`. Используйте `set_default_payload_handler` для ясности или `register_op_handler` для конкретных кодов операций.

#### `void set_on_disconnect_callback(OnDisconnectCallback callback)`
Устанавливает функцию обратного вызова, которая будет вызвана при отключении клиента от сервера.
- **Сигнатура:** `std::function<void()>`

---

## `session.hpp`

Основной класс для управления состоянием сессии.

### `enum class Role`
Определяет роль текущей стороны.
- `CLIENT`: Сессия является клиентом.
- `SERVER`: Сессия является сервером.

### `class ObscuraProto::Session`
Управляет состоянием сессии, включая рукопожатие и обмен данными.

#### `Session(Role role, KeyPair server_sign_key)`
Конструктор сессии.
- `role`: Роль этой сессии (`CLIENT` или `SERVER`).
- `server_sign_key`:
    - Для **сервера**: полная долгосрочная пара ключей подписи (публичный и приватный).
    - Для **клиента**: пара, содержащая только публичный ключ подписи сервера.

- `struct ClientHello`: Сообщение от клиента к серверу. Содержит список поддерживаемых версий и эфемерный публичный ключ клиента.
- `struct ServerHello`: Сообщение от сервера к клиенту. Содержит выбранную версию, эфемерный публичный ключ сервера и его подпись.

Эти структуры были перенесены в `handshake_messages.hpp`.

### Методы рукопожатия

#### `ClientHello client_initiate_handshake()`
**Для клиента.** Инициирует рукопожатие. Генерирует эфемерную пару ключей и создает `ClientHello`.
- **Выбрасывает:** `LogicError`, если вызывается на стороне сервера.

#### `ServerHello server_respond_to_handshake(const ClientHello& client_hello)`
**Для сервера.** Обрабатывает `ClientHello`, генерирует свою эфемерную пару, вычисляет сессионные ключи и возвращает `ServerHello`.
- **Выбрасывает:** `LogicError`, если вызывается на стороне клиента; `RuntimeError` при несовместимости версий или сбое крипто-операций.

#### `void client_finalize_handshake(const ServerHello& server_hello)`
**Для клиента.** Завершает рукопожатие. Проверяет подпись сервера и вычисляет сессионные ключи.
- **Выбрасывает:** `LogicError`, если вызывается до `client_initiate_handshake`; `RuntimeError` при неверной подписи или сбое крипто-операций.

### Методы обмена данными

#### `EncryptedPacket encrypt_payload(const Payload& payload)`
Шифрует `Payload`. Автоматически увеличивает счётчик отправленных сообщений.
- **Выбрасывает:** `LogicError`, если рукопожатие не завершено.

#### `Payload decrypt_packet(const EncryptedPacket& packet)`
Расшифровывает `EncryptedPacket`. Проверяет счётчик сообщений для защиты от replay-атак.
- **Возвращает:** `Payload` в случае успеха.
- **Выбрасывает:** `LogicError`, если рукопожатие не завершено; `RuntimeError` при сбое расшифровки или обнаружении replay-атаки.

### Прочие методы

#### `bool is_handshake_complete() const`
Проверяет, было ли успешно завершено рукопожатие.
- **Возвращает:** `true`, если сессия готова к обмену данными.

### Методы идентификации клиента

#### `void set_client_identity_key(KeyPair identity_kp)`
**Для клиента.** Устанавливает пару ключей Ed25519 для аутентификации клиента. При установке вызов `client_initiate_handshake()` будет включать публичный ключ и подпись эфемерного ключа X25519.
- **Выбрасывает:** `LogicError`, если вызывается на стороне сервера.

#### `bool has_peer_identity() const`
Проверяет, предоставил ли подключенный клиент и была ли успешно проверена его идентификация Ed25519.
- **Возвращает:** `true`, если у клиента есть проверенная идентификация.

#### `std::optional<PublicKey> get_peer_identity() const`
Возвращает проверенный публичный ключ Ed25519 подключенного клиента.
- **Возвращает:** Публичный ключ клиента или `std::nullopt`, если идентификация не была предоставлена.

---

## Константы протокола

### `constexpr uint16_t RESPONSE_OP_CODE = 0xFFFF`
Внутренний код операции, используемый механизмом "запрос-ответ" для идентификации сообщения-ответа. Этот код обрабатывается внутренне `WsClientWrapper` и `WsServerWrapper` и обычно не раскрывается логике приложения.
