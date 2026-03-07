# p2p-chat

**[English version below ↓](#english)**

---

## Описание

Минималистичный зашифрованный P2P-чат для локальной сети (1-на-1). Работает поверх TCP, использует NDJSON-фрейминг и полноценное E2EE на основе библиотеки NaCl.


### Ключевые особенности

- **E2EE** — сообщения шифруются до отправки и расшифровываются только получателем (XSalsa20-Poly1305 через NaCl `SecretBox`)
- **Аутентификация по ключу** — у каждого узла есть постоянный Ed25519-ключ идентичности; `peer_id = SHA256(IK_pub)`. Перед соединением стороны обмениваются *контактными карточками* и сохраняют публичные ключи друг друга
- **Эфемерные сессионные ключи** — при каждом соединении генерируется новая пара X25519; компрометация долгосрочного ключа не раскрывает прошлые сессии
- **Надёжная доставка** — каждое сообщение имеет уникальный `msg_id` и ждёт `ACK`. При отсутствии подтверждения повторная отправка происходит до 7 раз с интервалом 3 секунды, после чего сообщение помечается как `FAILED`
- **Контактные карточки и QR-коды** — идентичность передаётся в виде компактного JSON, который можно распечатать как ASCII QR-код

---

## Требования

- Python 3.10+
- Зависимости из `requirements.txt`:

```
PyNaCl>=1.5.0
qrcode>=7.4.2
```

Установка:

```bash
pip install -r requirements.txt
```

---

## Структура проекта

| Файл | Назначение |
|---|---|
| `main.py` | Точка входа, CLI-аргументы |
| `peer.py` | Логика узла: состояния, рукопожатие, шифрование, отправка/приём |
| `protocol.py` | Форматы сообщений, кодирование/декодирование NDJSON |
| `identity.py` | Загрузка или генерация постоянного Ed25519-ключа, вычисление `peer_id` |
| `contacts.py` | Контактная книга (JSON): чтение, запись, поиск, обновление |
| `qr_contact.py` | Создание и валидация контактных карточек, вывод ASCII QR |
| `config.py` | Зарезервировано под параметры конфигурации |
| `identity.json` | Хранилище приватного ключа (создаётся автоматически) |
| `contacts.json` | Хранилище контактов (создаётся автоматически) |

---

## Быстрый старт

### Шаг 1 — Сгенерировать и передать контактную карточку

На машине **Alpha** выполни:

```bash
python main.py --name Alpha --host 192.168.0.100 --port 9000 --qr
```

В терминале появится строка JSON и ASCII QR-код. Сохрани JSON-строку в файл, например `cardA.json`.

На машине **Beta**:

```bash
python main.py --name Beta --host 192.168.0.107 --port 9000 --qr
```

Сохрани в `cardB.json`.

> Содержимое карточки:
> ```json
> {"v": 1, "peer_id": "4494...", "ik_pub": "/CKE...", "name": "Alpha", "hint": {"host": "192.168.0.100", "port": 9000}}
> ```

### Шаг 2 — Импортировать карточки друг друга

На машине Alpha:

```bash
python main.py --name Alpha --import-card-file cardB.json
```

На машине Beta:

```bash
python main.py --name Beta --import-card-file cardA.json
```

Альтернативно, можно передать карточку строкой (например, в PowerShell):

```bash
python main.py --name Alpha --import-card "{\"v\":1,\"peer_id\":\"625d...\",...}"
```

### Шаг 3 — Запустить чат

Запустить слушателя на машине Alpha:

```bash
python main.py --name Alpha --listen --host 192.168.0.100 --port 9000
```

Подключиться с машины Beta:

```bash
python main.py --name Beta --connect --host 192.168.0.100 --port 9000
```

Когда на обеих сторонах появится `SECURE session established` — можно печатать сообщения и отправлять их нажатием Enter.

---

## Протокол (обзор)

Транспорт — TCP. Фрейминг — NDJSON (один JSON-объект на строку, разделитель `\n`).

### Состояния соединения

```
DISCONNECTED → CONNECTED → HANDSHAKE → SECURE → CLOSED
```

### Типы сообщений (внешние)

| Тип | Описание |
|---|---|
| `HELLO` | Первое сообщение после TCP-соединения, анонс `peer_id` |
| `HS1` | Handshake: передача `IK_pub`, `EK_pub` и Ed25519-подписи эфемерного ключа |
| `SECURE` | Зашифрованный конверт (nonce + ciphertext) для всех сообщений после установки сессии |

### Установка сессии

1. Стороны обмениваются `HELLO` → запускают `HS1`
2. Каждая сторона проверяет: `peer_id == SHA256(ik_pub)`, публичный ключ совпадает с сохранённым в контактах, подпись валидна
3. Через X25519 DH вычисляется общий секрет → `session_key = SHA256(shared_secret)[:32]`
4. Все дальнейшие сообщения — только через `SECURE`-конверт

### Внутренние типы (внутри SECURE)

- `CHAT` — текстовое сообщение с `msg_id` и порядковым номером `seq`
- `ACK` — подтверждение доставки: `ok` для нового, `dup` для дубликата

---

## Важно про файлы данных

`identity.json` и `contacts.json` создаются автоматически в рабочей директории. **Не передавай `identity.json` никому** — это твой приватный ключ.

---
---

<a name="english"></a>

# p2p-chat (English)

A minimal end-to-end encrypted peer-to-peer chat for local networks (1-to-1). Built on TCP with NDJSON framing and NaCl-based E2EE.

### Key features

- **E2EE** — messages are encrypted before leaving your machine and decrypted only by the recipient (XSalsa20-Poly1305 via NaCl `SecretBox`)
- **Key-based authentication** — each node has a persistent Ed25519 identity key; `peer_id = SHA256(IK_pub)`. Before connecting, peers exchange *contact cards* and pin each other's public keys
- **Ephemeral session keys** — a fresh X25519 key pair is generated per session; compromising the long-term identity key does not expose past sessions
- **Reliable delivery** — every message has a unique `msg_id` and waits for an `ACK`. Unacknowledged messages are retried up to 7 times with a 3-second timeout, then marked `FAILED`
- **Contact cards & QR codes** — identity is shared as a compact JSON card, printable as an ASCII QR code

---

## Requirements

- Python 3.10+
- Dependencies from `requirements.txt`:

```
PyNaCl>=1.5.0
qrcode>=7.4.2
```

Install:

```bash
pip install -r requirements.txt
```

---

## Project structure

| File | Purpose |
|---|---|
| `main.py` | Entry point, CLI argument parsing |
| `peer.py` | Node logic: state machine, handshake, encryption, send/receive |
| `protocol.py` | Message formats, NDJSON encode/decode helpers |
| `identity.py` | Load or generate persistent Ed25519 identity, derive `peer_id` |
| `contacts.py` | JSON contact book — load, save, lookup, upsert |
| `qr_contact.py` | Build and validate contact cards, print ASCII QR |
| `config.py` | Reserved for configuration constants |
| `identity.json` | Private key storage (auto-created) |
| `contacts.json` | Contact book storage (auto-created) |

---

## Quick start

### Step 1 — Generate and share your contact card

On **Alpha's** machine:

```bash
python main.py --name Alpha --host 192.168.0.100 --port 9000 --qr
```

This prints a JSON line and an ASCII QR code. Save the JSON to a file, e.g. `cardA.json`.

On **Beta's** machine:

```bash
python main.py --name Beta --host 192.168.0.107 --port 9000 --qr
```

Save to `cardB.json`.

> Card format:
> ```json
> {"v": 1, "peer_id": "4494...", "ik_pub": "/CKE...", "name": "Alpha", "hint": {"host": "192.168.0.100", "port": 9000}}
> ```

### Step 2 — Import each other's contact cards

On Alpha's machine:

```bash
python main.py --name Alpha --import-card-file cardB.json
```

On Beta's machine:

```bash
python main.py --name Beta --import-card-file cardA.json
```

You can also pass the card as an inline string (e.g. in PowerShell):

```bash
python main.py --name Alpha --import-card "{\"v\":1,\"peer_id\":\"625d...\",...}"
```

### Step 3 — Start chatting

Start the listener on Alpha's machine:

```bash
python main.py --name Alpha --listen --host 192.168.0.100 --port 9000
```

Connect from Beta's machine:

```bash
python main.py --name Beta --connect --host 192.168.0.100 --port 9000
```

Once both sides show `SECURE session established`, type a message and press Enter to send.

---

## Protocol overview

Transport: TCP. Framing: NDJSON (one JSON object per line, delimited by `\n`).

### Connection states

```
DISCONNECTED → CONNECTED → HANDSHAKE → SECURE → CLOSED
```

### Message types (outer)

| Type | Description |
|---|---|
| `HELLO` | First message after TCP connect, announces `peer_id` |
| `HS1` | Handshake: sends `IK_pub`, `EK_pub`, and an Ed25519 signature over the ephemeral key |
| `SECURE` | Encrypted envelope (nonce + ciphertext) used for all post-handshake messages |

### Session establishment

1. Both sides exchange `HELLO` → trigger `HS1`
2. Each side verifies: `peer_id == SHA256(ik_pub)`, the public key matches the one stored in contacts, and the signature is valid
3. X25519 DH produces a shared secret → `session_key = SHA256(shared_secret)[:32]`
4. All further communication is wrapped in `SECURE` envelopes only

### Inner message types (inside SECURE)

- `CHAT` — text message with a `msg_id` and sequence number `seq`
- `ACK` — delivery confirmation: `ok` for a new message, `dup` for a duplicate

---

## Data files

`identity.json` and `contacts.json` are created automatically in the working directory. **Never share `identity.json`** — it contains your private key.
