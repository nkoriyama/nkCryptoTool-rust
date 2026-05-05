# nkCryptoTool Technical Specification

This document provides a detailed technical specification of the `nkCryptoTool` Rust implementation.

## 1. System Architecture

`nkCryptoTool` is a high-performance, security-focused cryptographic utility designed for local file protection and secure network communication.

### 1.1 Components
- **CLI Wrapper**: Handles command-line arguments and configuration (`main.rs`, `config.rs`).
- **Core Processor**: Manages high-level cryptographic workflows (`processor.rs`).
- **Cryptographic Backends**: Abstracted interface for different implementations (`src/backend/`).
    - **OpenSSL Backend**: High-performance, FIPS-compliant operations.
    - **RustCrypto Backend**: Pure-Rust alternative for portability.
- **Network Processor**: Implements the NKCT protocol for secure file transfer and chat (`network.rs`).
- **Key Management**: Handles key generation, storage, and TPM integration (`src/key/`, `utils.rs`).

---

## 2. Cryptographic Specifications

### 2.1 Cryptographic Modes
- **ECC**: Classical Elliptic Curve Cryptography (Prime256v1/X25519).
- **PQC**: Pure Post-Quantum Cryptography (ML-KEM, ML-DSA).
- **Hybrid**: Combines ECC and PQC to ensure security against both classical and future quantum threats.

### 2.2 Algorithms
| Category | Supported Algorithms |
| :--- | :--- |
| **Key Encapsulation (KEM)** | ML-KEM-512, ML-KEM-768 (Default), ML-KEM-1024 |
| **Hybrid KEM** | ML-KEM + ECDH (P-256) |
| **Digital Signatures (DSA)** | ML-DSA-44, ML-DSA-65 (Default), ML-DSA-87 |
| **AEAD (Symmetric)** | AES-256-GCM (Default), ChaCha20-Poly1305 |
| **Hash & HKDF** | SHA3-256, SHA3-512 |

### 2.3 Key Storage Formats
- **Private Keys**: PKCS#8 encoded. PQC keys use custom OIDs as specified in Draft NIST standards.
- **Public Keys**: SubjectPublicKeyInfo (SPKI) encoded.
- **TPM Blobs**: Custom PEM format (`-----BEGIN TPM WRAPPED BLOB-----`) containing the public and private parts of a TPM-wrapped key.

---

## 3. Network Protocol Specification (NKCT)

The NKCT protocol provides a secure, authenticated, and quantum-resistant tunnel for data transfer. It is designed to be resilient against man-in-the-middle attacks and future quantum threats. The current implementation does not transmit a protocol version or AEAD name on the wire; both peers must agree on these via configuration prior to handshake.

### 3.1 Configuration Prerequisites
- **AEAD Algorithm**: Both peers must be configured with the same AEAD algorithm (`--aead-algo`, default `AES-256-GCM`). Mismatch results in an authentication failure during the first encrypted exchange.
- **PQC Algorithms**: KEM (`--kem-algo`, default `ML-KEM-768`) and DSA (`--dsa-algo`, default `ML-DSA-65`) must match.
- **Authentication Mode**: `--allow-unauth` defaults to `false` (mutual authentication required).

### 3.2 Handshake Sequence
The handshake follows a strict order to establish a secure session:

1.  **Client Hello**:
    - **Client ECC Public Key**: Length-prefixed (4-byte u32 LE) DER bytes.
    - **Client KEM Public Key**: Length-prefixed raw bytes.
    - **Authentication Flag**: 1 byte (`0x01` if signing, `0x00` otherwise).
    - **[Optional] Client Signature**: Length-prefixed ML-DSA signature over the current transcript (sent only if Authentication Flag = `0x01`).
2.  **Server Hello**:
    - **Server ECC Public Key**: Length-prefixed DER bytes.
    - **Server KEM Ciphertext**: Length-prefixed encapsulation bytes.
    - **Authentication Flag**: 1 byte (`0x01` if signing, `0x00` otherwise).
    - **[Optional] Server Signature**: Length-prefixed ML-DSA signature over the full transcript.

All length-prefixed fields are subject to an 8 KB upper bound (`read_vec` enforced) to prevent memory exhaustion via length stuffing.

### 3.3 Transcript Construction and Signature
The transcript is a byte array used for both authentication (signing) and session key derivation. It is updated incrementally.

- **Transcript Update Rule**: Every length-prefixed field is appended to the transcript prefixed with its 4-byte Little-Endian length.
- **Client Transcript Components** (in order):
    1. Client ECC Public Key (prefixed)
    2. Client KEM Public Key (prefixed)
    3. Client Auth Flag (1 byte, no length prefix)
- **Server Transcript Components**:
    1. [Client Transcript]
    2. Server ECC Public Key (prefixed)
    3. Server KEM Ciphertext (prefixed)
    4. Server Auth Flag (1 byte, no length prefix)

#### Why `auth_flag` is included in the Signature:
The `auth_flag` is explicitly included in the transcript and signed to prevent **Authentication Stripping Attacks**. If it were not signed, a man-in-the-middle could flip the bit from `1` to `0` and remove the signature field, tricking both parties into an unauthenticated session even when both required authentication.

### 3.4 Key Derivation and Salt
Once the handshake is complete, both parties derive symmetric keys:

1.  **Combined Shared Secret**: `ECC_Shared_Secret || KEM_Shared_Secret`.
2.  **Salt Generation**: `Salt = SHA3-256(Full Handshake Transcript)`. Using the full transcript as salt ensures that the session keys are uniquely bound to the specific handshake, including all public keys and algorithm choices.
3.  **HKDF Expansion**:
    - `PRK = HKDF-Extract(Salt, Combined_Shared_Secret)`
    - `s2c-key = HKDF-Expand(PRK, "s2c-key", 32)`
    - `s2c-iv = HKDF-Expand(PRK, "s2c-iv", 12)`
    - `c2s-key = HKDF-Expand(PRK, "c2s-key", 32)`
    - `c2s-iv = HKDF-Expand(PRK, "c2s-iv", 12)`

### 3.5 AEAD Packet Format

#### File Transfer Mode (Streaming)
Data is transferred in multiple chunks:
- **Chunk Header**: 4 bytes (u32 LE) - Length of the following encrypted chunk.
- **Encrypted Chunk**: `AEAD_Update(Plaintext)` - Ciphertext only.
- **Terminator**: 4 bytes of `0x00000000` (zero length) indicates end of stream.
- **Authentication Tag**: 16 bytes - The final MAC tag generated by `AEAD_Finalize`.

#### Chat Mode (Packet-based)
Each message is a self-contained AEAD packet:
- **Packet Header**: 4 bytes (u32 LE) - Total length of the following packet (`12 + Ciphertext_Len + 16`).
- **Nonce (IV)**: 12 bytes - Randomly generated for every packet.
- **Ciphertext**: `AEAD_Seal(Plaintext)` - The encrypted message.
- **Authentication Tag**: 16 bytes - MAC tag for this specific packet.

### 3.6 Nonce Management and Replay Protection

#### Nonce Rules:
- **Generation**: Nonces are generated using a cryptographically secure RNG (OpenSSL `RAND_bytes` or Rust `OsRng`).
- **Uniqueness**: A nonce MUST NEVER be reused with the same key. In Chat mode, a new random 12-byte nonce is generated for every single message.
- **Re-initialization**: In Chat mode, the AEAD state is re-initialized for every packet using the transmitted nonce and the static session key.

#### Anti-Replay Mechanism:
- **Nonce History**: Each party maintains a `HashSet` paired with a `VecDeque` for sliding-window expiration (capped at 100,000 entries). When the cap is reached, the oldest nonce is dropped from both structures rather than terminating the session, allowing long-running chats to remain usable.
- **Detection**: If a packet arrives with a nonce already present in the history, it is rejected as a **Replay Attack**, and the session is immediately terminated.
- **Scope**: Replay protection is per-session. Since session keys are unique (due to unique ephemeral DH/KEM keys and transcript-based salt), nonces cannot be replayed across different sessions.

### 3.7 Network Hardening and Timeouts
- **Handshake Timeout**: 15 seconds default, configurable via `--handshake-timeout` (prevents connection hanging during key exchange).
- **Idle Timeout**: 300 seconds (disconnects inactive clients).
- **Cumulative Session Timeout**: 2 hours for file transfer (mitigates "Slow Sender" attacks).
- **Chat Session Timeout**: 2 hours for chat sessions (caps maximum session duration).
- **Concurrency Control**: A global semaphore limits the server to 100 simultaneous active tasks to prevent resource exhaustion.

### 3.8 Peer Identity and Cooldown (Chat Mode)
Chat sessions use a layered DoS-defense scheme based on peer identity:

- **PeerId**: An enum representing a peer's identity:
    - `PeerId::Pubkey([u8; 32])`: SHA3-256 fingerprint of the peer's long-term ML-DSA signing public key (used after successful authentication).
    - `PeerId::Ip(IpAddr)`: Source IP fallback for unauthenticated peers (only when `--allow-unauth` is set).
- **PEER_COOLDOWNS**: A global `parking_lot::Mutex<HashMap<PeerId, Instant>>` storing the last-disconnect time for each peer. Old entries (>2 minutes) are pruned on each new connection.
- **Cooldown Duration**: After a chat session ends (any reason), the peer is barred from re-establishing chat for 60 seconds.
- **Early IP Cooldown (Flood Protection)**: Same-IP reconnection within 2 seconds is rejected at the `accept()` stage before `tokio::spawn` to save handshake resources.
- **Single Slot**: A global `CHAT_ACTIVE: AtomicBool` ensures at most one chat session is active at a time. The `ChatActiveGuard` RAII guard records cooldown and releases the slot on Drop.

### 3.9 Peer Allowlist
For deployments requiring strict access control, an explicit allowlist can be configured:

- **Configuration**: `--peer-allowlist <path>` accepts a text file with one SHA3-256 fingerprint per line (32 bytes hex). Comments (`#`) and blank lines are ignored.
- **Enforcement**: When an allowlist is loaded, peers whose long-term pubkey fingerprint is not in the set are rejected immediately after handshake authentication.
- **Loading**: The allowlist is loaded once at startup. Reloading requires a process restart.
- **Anonymous Peers**: When an allowlist is active, anonymous (unauthenticated) peers are rejected unless `--allow-unauth` is also set.
- **Use Case**: Combined with the default `allow_unauth=false`, this raises the cost of "many-key DoS" attacks (an attacker would need to obtain a pubkey on the allowlist).

---

## 4. Security Mechanisms

### 4.1 Memory Protection
- **Zeroization**: The `zeroize` crate is used throughout the codebase. `Zeroizing<T>` wrappers ensure keys and sensitive buffers are wiped from memory immediately after use or when they go out of scope.
- **Memory Locking**: `libc::mlock` is applied to sensitive buffers (where supported) to prevent them from being written to swap space.
- **Core Dump Prevention**: Core dumps are disabled via `setrlimit` at process startup.

### 4.2 TPM 2.0 Integration
- **Key Wrapping**: Keys can be wrapped by the TPM, binding them to the hardware.
- **HMAC Sessions**: TPM operations use authenticated HMAC sessions to prevent bus snooping and man-in-the-middle attacks between the CPU and TPM.

### 4.3 Network Hardening
- **Timeouts**:
    - Handshake Timeout: 15 seconds (configurable via `--handshake-timeout`).
    - Idle Timeout: 300 seconds.
    - Cumulative Session Timeout (file transfer): 2 hours.
    - Chat Session Timeout: 2 hours.
- **Resource Limits**:
    - Maximum concurrent connections: 100 (managed via Semaphore).
    - Max chunk size: 1 MiB.
    - Max handshake vector size: 8 KiB (`read_vec`).
    - Max file size per session: 10 GiB.
- **Anti-Replay**:
    - Chat mode maintains a sliding-window history of the last 100,000 nonces to prevent packet replay.
- **Peer-level DoS Defense**:
    - PeerId-based cooldown (60 seconds) tied to the long-term ML-DSA signing pubkey fingerprint.
    - Early IP-based flood protection (2 seconds, pre-spawn) to mitigate connection storms from a single source.
    - Optional `--peer-allowlist` for explicit access control.

---

## 5. Technical Implementation Details

### 5.1 Language & Dependencies
- **Language**: Rust (Edition 2021).
- **Async Runtime**: `tokio`.
- **Key Dependencies**:
    - `fips203`, `fips204`: NIST Post-Quantum standards.
    - `openssl`: High-performance backend.
    - `zeroize`: Memory security.
    - `clap`: Command-line interface.

### 5.2 Build Features
- `backend-openssl` (Default): Uses OpenSSL for all cryptographic operations including PQC. **Requires OpenSSL 3.5 or later** for native ML-KEM/ML-DSA support. Earlier versions will fail at PQC keygen.
- `backend-rustcrypto`: Pure-Rust implementations using `fips203` (ML-KEM), `fips204` (ML-DSA), `aes-gcm`, `chacha20poly1305`, `p256`, `sha3`, `pkcs8`. Supports all algorithms without external dependencies.

---

## 6. OID Definitions (PQC)

| Algorithm | OID |
| :--- | :--- |
| ML-KEM-512 | 2.16.840.1.101.3.4.4.1 |
| ML-KEM-768 | 2.16.840.1.101.3.4.4.2 |
| ML-KEM-1024 | 2.16.840.1.101.3.4.4.3 |
| ML-DSA-44 | 2.16.840.1.101.3.4.3.17 |
| ML-DSA-65 | 2.16.840.1.101.3.4.3.18 |
| ML-DSA-87 | 2.16.840.1.101.3.4.3.19 |

---

## 7. Authentication Policy

`nkCryptoTool` enforces a "Security by Default" policy regarding peer authentication.

### 7.1 Mutual Authentication (Mandatory by Default)
By default, the NKCT protocol requires mutual authentication using ML-DSA digital signatures. Both the client and the server must prove their identity by signing the handshake transcript with their respective private keys.
- **Fail-Safe**: If either party fails to provide a valid signature, or if the `auth_flag` indicates an unauthenticated session while authentication is required, the connection is immediately dropped.

### 7.2 The `--allow-unauth` Flag
The `--allow-unauth` flag is provided to bypass authentication requirements under specific circumstances.

- **Intended Use**: Strictly limited to development, local testing, and interoperability debugging.
- **Production Prohibition**: **Unauthenticated sessions MUST NEVER be used in production environments or over untrusted networks.**
- **Behavior**: When enabled, the tool will permit connections even if the peer does not provide a signature or if local signing keys are not configured.

### 7.3 Security Implications of Unauthenticated Sessions
When authentication is disabled via `--allow-unauth`, the following security guarantees are **LOST**:
1.  **Identity Verification**: There is no guarantee that you are communicating with the intended peer.
2.  **MITM Protection**: The session is vulnerable to Man-In-The-Middle (MITM) attacks where an attacker can intercept and potentially modify the traffic by substituting their own ephemeral keys.
3.  **Downgrade Protection**: An attacker can force the session into an unauthenticated state (Authentication Stripping) without detection.

### 7.4 Production Requirements
For all production deployments:
- **ML-DSA Keys**: Valid ML-DSA-65 (or higher) key pairs must be generated and exchanged out-of-band.
- **Strict Mode**: The `--allow-unauth` flag must be omitted to ensure the tool operates in its default, secure mode.
- **TPM Protection**: It is strongly recommended to protect long-term signing keys using the `--use-tpm` feature.

---

## 8. DoS Defense and Timeout Design

`nkCryptoTool` incorporates multiple layers of defense to protect against Denial-of-Service (DoS) attacks and resource exhaustion.

### 8.1 Connection and Resource Limits
- **Global Semaphore**: The server limits simultaneous active connections to **100** using a global semaphore. This prevents the tool from exhausting file descriptors, memory, or disk space through massive concurrent requests.
- **Task Holding**: Permits are held for the entire duration of the task, including final data release (e.g., writing to stdout), to ensure predictable resource usage even when dealing with slow output sinks.

### 8.2 Timeout Strategies
The protocol employs three distinct types of timeouts to mitigate different attack vectors:

| Timeout Type | Duration | Purpose |
| :--- | :--- | :--- |
| **HANDSHAKE_TIMEOUT** | 15 Seconds | Prevents "Half-Open" connection attacks where a client connects but never completes the CPU-intensive PQC handshake. |
| **IDLE_TIMEOUT** | 300 Seconds | Disconnects sessions that stop sending or receiving data. This applies to every chunk read/write operation in the data phase. |
| **CUMULATIVE_TIMEOUT** | 2 Hours | Protects against "Slow Sender" attacks. It limits the total duration of the data transfer phase, ensuring a single connection cannot occupy a semaphore slot indefinitely by sending data at a rate just high enough to avoid idle timeouts. |

### 8.3 Data and Memory Capping
- **MAX_CHUNK_SIZE**: Individual AEAD chunks are limited to **1 MiB** (`BUF_SIZE = 1024 * 1024`). This prevents large memory allocations from single malicious packets.
- **MAX_FILE_SIZE**: The server limits total received data per session to **10 GiB**. This protects against disk-filling attacks on the server's temporary storage.
- **Handshake Vector Limit**: All length-prefixed handshake vectors (ECC/KEM public keys, signatures) are limited to **8 KiB** by `read_vec`. This prevents memory exhaustion via length-prefix stuffing.
- **Nonce History Limit**: In Chat mode, the nonce store is capped at **100,000 entries**. When the cap is reached, the oldest entry is dropped (sliding window) rather than terminating the session, allowing long-running chats to remain usable.

### 8.4 Mitigation of "Slow Sender" Attacks
The combination of `IDLE_TIMEOUT` and `CUMULATIVE_TIMEOUT` is specifically designed to counter "Slow Sender" (Slowloris-style) attacks.
- Even if an attacker sends 1 byte every 299 seconds (avoiding the 300s idle timeout), the **2-hour cumulative limit** ensures that the resource slot will eventually be reclaimed, forcing the attacker to restart the expensive handshake process.

### 8.5 CPU Exhaustion Protection
While PQC algorithms (ML-KEM/ML-DSA) are more CPU-intensive than classical ECC, the tool mitigates CPU exhaustion by:
1.  Enforcing the `HANDSHAKE_TIMEOUT` before heavy processing starts.
2.  Utilizing `tokio::task::spawn_blocking` to prevent cryptographic operations from stalling the main async executor.
3.  Limiting total concurrent sessions (and thus concurrent handshakes) via the 100-slot semaphore.

---

## 9. Asynchronous Task Management (Tokio)

`nkCryptoTool` utilizes the `tokio` async runtime for high-performance network I/O. Task lifecycle management is carefully implemented to prevent resource leaks and ensure executor responsiveness.

### 9.1 Explicit Task Termination (`AbortGuard`)
By default, a task spawned with `tokio::spawn` continues to run even if its `JoinHandle` is dropped. To ensure that background tasks (such as the Chat receiver task) are cleaned up when the main loop exits:
- **AbortGuard**: A custom RAII wrapper is used. It stores the `AbortHandle` of a task and calls `.abort()` in its `Drop` implementation.
- This ensures that if the chat session ends (due to error or user exit), all associated background tasks are immediately and reliably terminated.

### 9.2 RAII State Management (`ChatActiveGuard`)
To prevent multiple concurrent chat sessions and ensure proper state cleanup:
- **ChatActiveGuard**: An RAII guard that holds the peer's identity (`peer_id: PeerId`) and start time.
- **On Drop**, the guard performs two synchronous actions:
    1. Records the peer's `PeerId` in `PEER_COOLDOWNS` with the current `Instant` (used for the 60-second cooldown).
    2. Resets `CHAT_ACTIVE` to `false`, allowing a new chat session to be accepted.
- The guard uses `parking_lot::Mutex` (no poisoning), so cleanup is safe even if a task panics during the chat loop.

### 9.3 Handling CPU-Bound Operations
Cryptographic operations (ML-KEM, ML-DSA, ECC-DH) are CPU-bound and can block the async executor's thread, leading to increased latency for other connections.
- **spawn_blocking**: All heavy cryptographic computations are offloaded to Tokio's blocking thread pool using `tokio::task::spawn_blocking`.
- This ensures the main async threads remain free to handle network I/O and manage other active sessions.

### 9.4 Graceful Shutdown and Panic Safety
- **Select Macro**: `tokio::select!` is used in the chat loop to handle multiple asynchronous events (stdin, network RX, task completion) simultaneously.
- **Panic Propagation**: Results from `spawn_blocking` and `tokio::spawn` are checked to ensure that panics in sub-tasks are caught and logged, preventing silent failures.

---

## 10. Sensitive Information Lifecycle

`nkCryptoTool` enforces a rigorous lifecycle for all sensitive information to minimize the window of exposure in memory. This is achieved through the consistent use of the `zeroize` crate and precise scoping.

### 10.1 Key Sensitive Entities
The following entities are identified as sensitive and are subject to strict management:

| Entity | Implementation | Lifecycle / Scope |
| :--- | :--- | :--- |
| **Passphrase** | `Zeroizing<String>` | Collected via `rpassword`, wrapped in `Zeroizing`, and dropped immediately after key derivation or TPM authentication. |
| **Private Keys** | `Zeroizing<Vec<u8>>` | Read from disk or TPM, wrapped in `Zeroizing` during decoding, and kept in memory only for the duration of the cryptographic operation (Signing/Decapping). |
| **ss_ecc** (ECC Shared Secret) | `Zeroizing<Vec<u8>>` | Generated by `ecc_dh`, immediately wrapped in `Zeroizing`, and moved into the `combined_ss`. |
| **kem_ss** (KEM Shared Secret) | `Zeroizing<Vec<u8>>` | Generated by `pqc_encap/decap`, immediately wrapped in `Zeroizing`, and moved into the `combined_ss`. |
| **combined_ss** | `Zeroizing<Vec<u8>>` | Concatenation of `ss_ecc` and `kem_ss`. Dropped immediately after the HKDF-Extract operation. |
| **Session Keys** | `Zeroizing<Vec<u8>>` | Derived via `HKDF-Expand`. Used to initialize the AEAD state and dropped upon session termination. |

### 10.2 Consistent Use of `Zeroizing`
All intermediate secrets, including the raw results of DH and KEM operations, are wrapped in `Zeroizing<T>` at the point of creation. This ensures that:
- **Automatic Wiping**: The memory is zeroed out as soon as the variable goes out of scope (e.g., at the end of a block or function).
- **Panic Safety**: Even if a thread panics, the `Drop` implementation of `Zeroizing` ensures that the secret material is cleared during stack unwinding.

### 10.3 Scope Minimization
Secrets are kept in memory for the minimum time required:
- **Handshake Secrets**: Shared secrets (`ss_ecc`, `kem_ss`, `combined_ss`) exist only within the handshake function scope. Once the HKDF operation is complete and the AEAD session keys are derived, these high-entropy secrets are wiped.
- **Signing Key Caching (Network Mode)**: For server availability and to prevent passphrase prompts during every handshake, the long-term signing private key is loaded **once at process startup** via `preload_signing_key`, decrypted (PBES2 if encrypted), and stored in `Arc<SecureBuffer>` (mlock'd). It persists for the lifetime of the process. This is a deliberate trade-off: process-lifetime memory residence in exchange for non-blocking handshakes. The cache is dropped when the `NetworkProcessor` goes out of scope.
- **Other Private Keys**: For local file operations (sign/decrypt), private keys are loaded just-in-time and dropped immediately after the operation completes.

### 10.4 Buffer Management
- **Plaintext Buffers**: During file encryption/decryption, plaintext chunks are processed in `Zeroizing` containers to ensure no residue of the original file content remains in memory after the chunk is encrypted and sent to the network or written to disk.
- **Mmap**: For large data processing, memory mapping is used to minimize copying, and sensitive regions are unmapped/zeroed where applicable.

## 12. Threat Model

The security of `nkCryptoTool` is analyzed against the following threat model, defining what the tool is designed to protect against and the assumed capabilities of an adversary.

### 12.1 Assumed Attacker Capabilities
An adversary is assumed to have the following capabilities:
- **Full Network Control**: The attacker can intercept, modify, drop, or replay any packet sent over the network. They can perform Man-In-The-Middle (MITM) attacks.
- **Local Read-Only Memory Access**: The attacker may be able to obtain a memory dump of the process (e.g., through an unprivileged local vulnerability).
- **Offline Analysis**: The attacker can store any captured traffic or encrypted files and perform exhaustive offline analysis or future quantum-based attacks.

### 12.2 Security Objectives (In-Scope)
- **Confidentiality**: Even with full network control and future quantum computers, the attacker cannot decrypt the communication or protected files.
- **Integrity & Authenticity**: Any modification to the traffic or files will be detected, and unauthenticated peers cannot spoof their identity.
- **Replay Protection**: Captured valid packets cannot be reused to trick the receiver into processing the same message twice.
- **Memory Residue Mitigation**: Sensitive data is wiped from memory as soon as possible to minimize the window where a memory dump could reveal secrets.

### 12.3 Out-of-Scope Threats
The following threats are explicitly **not** covered by the current design:
- **Timing Attacks**: Fine-grained side-channel attacks based on the timing of cryptographic operations or network responses.
- **Compromised OS/Kernel**: If the underlying operating system or kernel is compromised, no user-space tool can guarantee security.
- **Physical Attacks**: Hardware-level attacks such as cold boot attacks or physical probing of the TPM/CPU.
- **Abrupt Termination Cleanup**: While RAII handles normal panics, `SIGKILL` or hardware failure may prevent the final zeroization of memory.

`nkCryptoTool` is built upon the following foundational security principles. These are not merely implementation guidelines but mandatory invariants that must be preserved across all versions and refactorings.

### 11.1 No-Copy Principle
Copies of sensitive data (passphrases, keys, shared secrets) must be minimized. In cases where a copy is absolutely necessary for the protocol or implementation, the new copy must be immediately wrapped in a `Zeroizing` container.

### 11.2 Symmetry Principle
Security enhancements, bug fixes, and defensive measures must be applied symmetrically across the entire system:
- **Roles**: Both Client and Server implementations.
- **Modes**: Both Chat and File Transfer modes.
- **Algorithms**: All supported AEAD algorithms (AES-GCM, ChaCha20-Poly1305).

### 11.3 Boundary Preservation
Security properties, particularly the `Zeroizing` status and memory protection, must not be lost when data crosses boundaries, such as function calls, API returns, or asynchronous task transfers.

### 11.4 Explicit Destruction
While relying on RAII and the `Drop` trait for automatic cleanup, the principle of explicit destruction is preferred. Sensitive data should be zeroed as soon as its functional requirement is met, rather than waiting for the end of its lexical scope whenever practical.

### 11.5 Backend Distrust Model
External cryptographic libraries (OpenSSL, RustCrypto ecosystem) are treated as "trusted but verified" black boxes. The tool's design assumes that their internal states might not be perfect, and thus it enforces additional layers of protection (like manual zeroization and re-initialization) to mitigate potential backend-specific vulnerabilities.

### 11.6 State Machine Consistency
Any performance optimizations (e.g., the use of `re_init` instead of full re-allocation) must be mathematically and logically consistent with the intended cryptographic state transition model.

### 11.7 Memory-Agnostic Security
Sensitive material is treated with the same level of security rigor regardless of where it resides:
- **Stack**: Ephemeral variables.
- **Heap**: Long-lived containers and buffers.
- **Temporary Storage**: Scratchpads and intermediate calculation areas.

---

## 13. Known Limitations

While `nkCryptoTool` is designed with high security standards, certain technical trade-offs and theoretical vulnerabilities exist.

### 13.1 Streaming AEAD "Verify-Before-Write" Trade-off
In Streaming AEAD mode (File Transfer), the tool processes data in chunks.
- **Limitation**: It is impossible to perform a full authentication check on a multi-gigabyte stream before writing the initial bytes to a destination (disk or stdout) without buffering the entire stream in memory, which is impractical.
- **Mitigation**: The server implementation uses a temporary file to store incoming data and only releases it to stdout after the final AEAD tag is successfully verified. However, on the client-side or in direct pipe scenarios, partial data may be written before the authentication failure is detected at the end of the stream.

### 13.2 Very Low Bandwidth DoS
The tool implements multiple timeouts to prevent resource exhaustion.
- **Limitation**: An attacker can theoretically perform a "Very Low Bandwidth DoS" by sending data at a rate just fast enough to satisfy the `IDLE_TIMEOUT` (e.g., 1 byte every 299 seconds).
- **Mitigation**: This attack is time-bounded by the `CUMULATIVE_TIMEOUT` (2 hours). While an attacker can occupy one of the 100 semaphore slots for 2 hours, they cannot do so indefinitely. A sustained attack would require a large number of IPs and the repeated performance of CPU-intensive handshakes.

### 13.3 Nonce HashSet Memory Limit
In Chat mode, the nonce history is capped at 100,000 entries with sliding-window expiration (oldest dropped on overflow).
- **Limitation**: Replay protection is theoretically weakened for messages older than 100,000 entries. In practice, a chat would need to receive 100,000 messages within the session before this matters.
- **Future Roadmap**: Moving to a 64-bit monotonic counter for nonces would provide infinite replay protection with constant O(1) memory overhead.

### 13.4 Memory Residence of Cached Signing Key (Network Mode)
The long-term signing private key cached in `Arc<SecureBuffer>` resides in process memory for the entire process lifetime.
- **Limitation**: An attacker with local memory-read capability (e.g., `/proc/<pid>/mem`, `gcore`) can recover the key. `mlock` only prevents swapping to disk, not in-RAM scraping.
- **Mitigation**: The default deployment should run on hardened systems with `ptrace` restrictions (`kernel.yama.ptrace_scope=2` or `=3`).
- **Future Roadmap**: TPM-backed signing in network mode would obviate the need to hold raw key material in process memory.

### 13.5 Structural ASN.1 Parsing
PKCS#8 / SPKI parsing for PQC keys uses structured DER decoders via the `pkcs8` and `spki` crates.
- **Improvement**: Strict validation of OIDs and DER structures is now performed, significantly increasing robustness against malformed or maliciously crafted keys.
- **Future Roadmap**: Continuously update to the latest cryptographic standards as PQC specifications stabilize.
