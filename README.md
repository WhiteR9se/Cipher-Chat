# CipherChat – Secure Network Chat Platform

## 1. Executive Summary
CipherChat is a C++-only, end-to-end encrypted chat system that showcases modern network programming concepts while remaining easy to build and demonstrate. A lightweight relay (`./build/server`) brokers connections and room membership, but the relay never sees plaintext. Terminal clients (`./build/client`) negotiate keys, encrypt messages locally, and render the decrypted conversation. Captured packets, server-side room archives, and the running server log all display random ciphertext, making the confidentiality story easy to prove during a demo.

---

## 2. Key Capabilities
- **End-to-End Encryption** – All chat payloads are sealed with AES-256-GCM; the server forwards opaque envelopes only.
- **Ephemeral Key Exchange** – Each client performs an X25519 Diffie–Hellman exchange and derives session keys with HKDF-SHA256.
- **Room-Based Collaboration** – Users can list, join, leave, and create rooms on the fly. Room keys rotate whenever membership changes.
- **Live Presence Events** – Join, leave, and rename events are broadcast to everyone in the room, so participants always know who is present.
- **Structured Logging for Evidence** – `logs/server.log` records timestamped activity and ciphertext summaries; `logs/room_<id>.log` captures per-room ciphertext while the room is active.
- **Clean Shutdown** – Room logs are deleted automatically when the room empties or the relay exits; the default `server.log` persists across runs with blank separators.

---

## 3. System Architecture
```
   ┌──────────────────────┐                ┌──────────────────────┐
   │   Client (Terminal)  │  TCP + E2EE   │     Relay Server     │
   │  ./build/client      │◀─────────────▶│    ./build/server    │
   └──────────────────────┘                └──────────────────────┘
            ▲  ▲                                     │
            │  └── AES-256-GCM chat frames (nonce | ciphertext | tag)
            │
            └──── AES-256-GCM control frames (room keys, events, errors)
```

### 3.1 Relay Server Responsibilities
- Accept TCP connections and assign client IDs.
- Run an X25519 handshake per connection, deriving a dedicated control-key via HKDF-SHA256.
- Maintain room state: name, numeric ID, members, and current symmetric key.
- Re-wrap new room keys for members whenever someone joins/leaves.
- Persist ciphertext envelopes to `logs/room_<id>.log` while the room has participants.
- Publish join/leave/rename events and relay ciphertext frames to room members without decryption.

### 3.2 Client Responsibilities
- Initiate the handshake, derive the shared secret, and decrypt authenticated control frames.
- Encrypt outbound messages with AES-256-GCM using the room key and per-message nonces.
- Maintain a low-latency terminal interface with commands:
  - `/rooms`, `/join <name|id>`, `/leave`, `/rename <name>`, `/quit`
- Display presence notifications and decrypted chat messages in real time.

---

## 4. Security Design
| Layer              | Mechanism                                                     |
|--------------------|----------------------------------------------------------------|
| Key Agreement       | X25519 Diffie–Hellman; fresh key pair per client connection   |
| Key Derivation      | HKDF-SHA256 (32 bytes) with role-specific context strings     |
| Control Channel     | AES-256-GCM; AAD binds to the client ID                       |
| Chat Payloads       | AES-256-GCM; AAD binds to room ID and sender ID               |
| Forward Secrecy     | Achieved session-by-session (ephemeral keys). Room keys are re-issued whenever membership changes. |
| Integrity           | GCM tags prevent tampering or replay; mismatched tags drop frames silently |

**Evidence to show during demo**
- `logs/room_<id>.log` contains timestamped Base64 ciphertext lines, never plaintext.
- `logs/server.log` shows hexdigests of ciphertext in relay messages.
- Wireshark/TCPDump capture displays non-human-readable payloads.
- Clients alone render readable messages, demonstrating true end-to-end control of decryption.

---

## 5. Operational Behaviour
- **Startup**
  - `./build/server 7777` (default bind: `0.0.0.0`). Each start appends two blank lines to `logs/server.log` followed by timestamped entries.
  - The server creates the default "lobby" room (ID 1) and awaits connections.
- **Joining**
  - On connect, every client automatically joins the lobby, receives the roster, buffered messages (last 100), and a fresh room key.
  - Joining a new room emits a `leave` event in the previous room before broadcasting the `join` in the new room, keeping everyone informed.
- **Room Lifecycle**
  - Rooms are created on demand (`/join <name>`). Numeric join (`/join <id>`) is also supported.
  - When the final member leaves (excluding the lobby), the room state is destroyed and `logs/room_<id>.log` is deleted.
- **Shutdown**
  - `Ctrl+C` stops the accept loop, disconnects clients, clears in-memory state, deletes all `room_*.log` files and client history, but preserves `server.log` for auditing.

---

## 6. Build & Run Instructions
### 6.1 Prerequisites (Ubuntu / Debian)
```bash
sudo apt install build-essential cmake libssl-dev
```

### 6.2 Configure & Compile
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 6.3 Launching the System
```bash
# Terminal 1 – relay
./build/server 7777

# Terminal 2 – first participant
./build/client 127.0.0.1 7777 alice

# Terminal 3 – second participant
./build/client 127.0.0.1 7777 bob
```

After connecting, try:
- `/rooms` to inspect available rooms (output includes IDs and names).
- `/join project` to create/join a new room named "project".
- `/join 1` to jump back to the lobby.
- `/rename <newname>` to change your display name.
- `/quit` to exit a client.

---

## 7. Demonstration Script (2 Minutes)
1. **Handshake & Encryption** – Start the relay and two clients; point out the handshake log entries and AES key derivation messages in `server.log`.
2. **Confidential Messaging** – Exchange a few chat messages. Show the same timestamps appearing as Base64 ciphertext lines inside `logs/room_1.log`.
3. **Room Management** – Create a new room, join with both clients, and highlight join/leave notifications in both terminals and `server.log`.
4. **Network Sniffing** – Run `tcpdump -X -s0 port 7777` and display random-looking packet contents.
5. **Room Teardown** – Have both users leave the secondary room; demonstrate that `logs/room_<id>.log` disappears immediately.
6. **Shutdown** – Stop the server and show how `server.log` persists with clear timestamps while room logs are removed.

---

## 8. Testing & Validation Checklist
- [ ] Build succeeds on fresh environment (`cmake --build build`).
- [ ] Multiple clients can join the same room and exchange messages with low latency.
- [ ] `/join` emits leave notifications in the previous room; the roster updates correctly.
- [ ] Wireshark capture confirms no plaintext on the wire.
- [ ] When the relay exits, only `logs/server.log` remains.
- [ ] Unit smoke-test: mis-tagged ciphertext (alter any character in `logs/room_<id>.log`, replay via netcat) is rejected due to GCM authentication.

---

## 9. Future Enhancements
- Automated key rotation on a timer to tighten forward secrecy windows even further.
- User authentication backed by passwords or certificates (currently trust-on-first-use).
- File or clipboard sharing using the same encrypted transport.
- Rich Text User Interface (ncurses) or cross-platform GUI front-end.
- Load-balancing relay clusters with gossip-based room state replication.

---

CipherChat fulfills the networking project goals by combining non-blocking socket programming, cryptography, and thoughtful operational logging. The workflow is simple, the encryption story is demonstrable, and the codebase is modular enough for future research or coursework extensions.

