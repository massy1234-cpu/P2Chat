# P2Chat — Agent Context

## Project structure

```
P2Chat/
├── cmd/client/main.go                 # Entry point: watchdog + ML-DSA keygen demo
├── cmd/client/internals/
│   ├── argon/                         # Argon2id KDF (3 security levels)
│   ├── encryption/                    # AES-256-GCM, salt, commitment scheme
│   │   ├── mldsa_encryption/          # Encrypt ML-DSA private keys with Argon2+AES
│   │   └── encryption_hsm/TPM|SE/    # HSM key wrapping wrappers
│   ├── errors/                        # Watchdog (SIGINT/TERM/SEGV/BUS → memguard.Purge)
│   ├── HSM/TPM/                       # TPM sealed blobs (linux|windows)
│   │   └── linux_tpm.go / windows_tpm.go / common_tpm.go
│   ├── HSM/SE/                        # Secure Enclave P-256 ECIES (darwin, CGo)
│   │   └── macos_se_secret.go / macos_se_available.go
│   ├── keys/mldsa/                    # ML-DSA-87 keygen, sign, decode
│   ├── keys/mlkem/                    # ML-KEM-768 keygen, encapsulate, decapsulate
│   ├── keys/x25519/                   # X25519 ECDH + XEdDSA signatures
│   ├── network/                       # Networking layer
│   │   ├── TLS/
│   │   │   └── TLS.go                 # Server TLS + certificate (da integrare con Tor dialer)
│   │   ├── transmission/
│   │   │   ├── read.go                # ReadMessage: 4B size + 32B SHA-256 checksum header
│   │   │   └── write.go               # WriteMessage + CreateHeader
│   │   ├── structs/
│   │   │   ├── structs.go             # SingleSession, Connection (with Done), ConnectionManager
│   │   │   ├── session_methods.go     # NewSession, Listener (sentinel), Writer, Close
│   │   │   └── connection_methods.go  # NextID, ReleaseID, ListenOnWire, ReleaseSession, Close
│   │   ├── wrapper/
│   │   │   └── wrap_connection.go     # Wrapper: yamux.Client + ConnectionManager
│   │   ├── tor/
│   │   │   ├── tor.go                 # CreateConnectionTor (da fixare: return type, leak, panics)
│   │   │   └── tor_test.go            # Test di bootstrap Tor
│   │   └── certificate/
│   │       └── certificate.go         # Client TLS certificate generation
│   ├── p2log/                         # Colored console+file logger (Debug/Info/Warning/Error)
│   ├── p2version/                     # Magic bytes "P2CH1"
│   ├── proto/                         # .proto source definitions
│   ├── proto_generated/               # Generated .pb.go + methods.go (SetChecksum/VerifyChecksum)
│   ├── protocol/pqxdh/               # PQXDH bundle data structures
│   ├── storage/                       # File I/O for keys (SK.bin, PK.bin), BasePath init
│   └── bbolt/                         # BoltDB init (database/database.db)
├── pkg/apperr/                        # fmt.Errorf wrapper (Wrap, New)
├── cirl-custom/circl/                 # Forked CIRCL: ML-DSA-87 with memguard
├── docs/recap.md                      # Full design doc (2226 lines)
├── go.mod / go.sum                    # Module P2Chat, go 1.25.8
├── Makefile                           # proto + run targets
└── docker-compose.yml                 # server + client containers
```

## Commands

- `make proto` — regenerate protobuf: `protoc --go_out=. --go_opt=module=P2Chat cmd/client/internals/proto/mldsa/*.proto`
- `make run` — run proto + client: `cd cmd/client && go run .`
- `go test ./cmd/client/internals/...` — run all tests from module root
- `go test -v -run <TestName> ./path/to/package/` — focused test
- `go build ./cmd/client` — build da project root

## OS-specific packages (build tags)

| Package | Build Tags | Hardware |
|---------|-----------|---------|
| `HSM/TPM/` | `linux || windows` | TPM 2.0 via `/dev/tpmrm0` or `windowstpm` |
| `HSM/SE/` | `darwin` | Secure Enclave via Security.framework (CGo) |

All `HSM/` tests **skip gracefully** when hardware is unavailable (no special test setup needed).

## macOS SE signing sequence (for tests)

```bash
cd cmd/client/internals/HSM/SE
go test -c -o macos.test .
cp macos.test macos_test.app/Contents/MacOS/macos.test
codesign -f -s 945E1AD0FA3F22DB91B66BA52E00293ACC452238 \
  --entitlements entitlements_storage.plist macos_test.app
./macos_test.app/Contents/MacOS/macos.test -test.v
```

## macOS SE signing sequence (for app binary)

Any binary that accesses the Secure Enclave must be codesigned inside a `.app` bundle.
Use this script after every build:

```bash
go build -o p2chat ./cmd/client
mkdir -p p2chat.app/Contents/MacOS
cp p2chat p2chat.app/Contents/MacOS/p2chat
cp cmd/client/internals/HSM/SE/macos_test.app/Contents/embedded.provisionprofile p2chat.app/Contents/
cp cmd/client/internals/HSM/SE/macos_test.app/Contents/Info.plist p2chat.app/Contents/
codesign -f -s 945E1AD0FA3F22DB91B66BA52E00293ACC452238 \
  --entitlements cmd/client/internals/HSM/SE/entitlements_storage.plist \
  p2chat.app
./p2chat.app/Contents/MacOS/p2chat
```

Also applies to any test binary that calls `EncryptHSM` / `SE.Encrypt` from a
package other than `HSM/SE/` itself (e.g. `encryption_hsm/hsm_encrypt_test.go`):

```bash
cd cmd/client/internals/encryption/encryption_hsm
go test -c -o hsm_encrypt.test .
mkdir -p hsm_test.app/Contents/MacOS
cp hsm_encrypt.test hsm_test.app/Contents/MacOS/hsm_encrypt
cp ../../HSM/SE/macos_test.app/Contents/embedded.provisionprofile hsm_test.app/Contents/
hsm_test.app/Contents/Info.plist  # create minimal Info.plist if missing
codesign -f -s 945E1AD0FA3F22DB91B66BA52E00293ACC452238 \
  --entitlements ../../HSM/SE/entitlements_storage.plist hsm_test.app
./hsm_test.app/Contents/MacOS/hsm_encrypt -test.v
```

Provisioning profile expires every 7 days (free Apple account). Refresh from Xcode:
```bash
find ~/Library/Developer/Xcode/DerivedData -path '*/Build/Products/Debug/p2chat.app/Contents/embedded.provisionprofile' -print
```

**SE error -34018 (`errSecInteractionNotAllowed`)?** → il binario non è firmato
correttamente. Segui la procedura sopra per build + .app + codesign.

## Security conventions

- **All secrets in `memguard.LockedBuffer`** (mlock'd, no swap). Never use plain `[]byte` for passwords, keys, or secrets.
- **Never do:** `defer memguard.WipeBytes(aesKey.Bytes())` — `.Bytes()` returns a reference to the locked buffer; wiping it destroys the original. Copy to a temp slice first if you must wipe.
- **Prefer `.Bytes()` directly** over copying into a temporary slice (reduces exposure window).
- **`memguard.Enclave`** for encrypted-at-rest in memory (keys not in active use). Call `.Open()` to decrypt temporarily.
- **Type conventions:**
  - `*memguard.Enclave` → chiavi private persistenti (la funzione chiama `.Open()` internamente)
  - `*memguard.LockedBuffer` → segreti a breve durata (buffer mlock'd, va distrutto subito dopo l'uso)
  - `[]byte` → dati pubblici, ciphertext, nonce, salt, firme
- **Argon2id levels:** 1=low (fast), 2=medium, 3=high (slow, high memory). Don't invert them.
- **Watchdog goroutine** runs at startup (`errors.Watchdog()`). Purges mlock'd memory on SIGINT/SIGTERM/SIGSEGV/SIGBUS.
- **SHA-256 checksums** on protobuf payloads via `SetChecksum()`/`VerifyChecksum()`.

## Key file locations on disk

All paths are relative to `storage.BasePath`, auto-resolved to `<project_root>/data/` via `init()`.

| File | Relative Path | Content |
|------|--------------|---------|
| ML-DSA keys (per bundle) | `bundle_{ID}_IK_keys/SK.bin` | Encrypted ML-DSA private key (protobuf) |
| ML-DSA keys (per bundle) | `bundle_{ID}_IK_keys/PK.bin` | ML-DSA public key (protobuf, plaintext) |
| X25519 IK (per bundle) | `bundle_{ID}_IK_keys/IK_X25519.bin` | Encrypted X25519 identity private key (msgpack) |
| TPM blobs | `blobs/privateBlob.bin` + `publicBlob.bin` | TPM-sealed secret |
| SE blob | `SE_BLOB.bin` | ECIES-encrypted 32-byte payload |
| BoltDB | `database/database.db` | Future: PQXDH bundles, sessions, contacts |

## Key types

- **ML-DSA-87**: Post-quantum signatures (FIPS 204). Key sizes: 32B seed, ~2592B public, ~4864B private.
- **ML-KEM-768**: Post-quantum KEM (FIPS 203). Key sizes: 1184B public, 2400B private, 32B shared secret, 1088B ciphertext.
- **X25519**: Classic ECDH (32B keys). Also used for XEdDSA signatures.

## ML-KEM important note

`sharedSecret` from ML-KEM must NOT be used directly as an AES key. It must go through a KDF first (standard practice).

## Known quirks

- `client` at repo root is a compiled binary (Mach-O arm64), not a directory.
- `make proto` must be run from project root (where `go.mod` lives), not from `cmd/client/`.
- TPM `Inizialize()` creates new blobs each call (not idempotent); `LoadBlobs` must be used instead after the first init.
- `TestSEEncryptKey` fails with error -34018 on non-signed/non-provisioned macOS (requires codesign + provisioning profile).
- `EncryptAes256` returns error on nil key — callers must check.
- `hsm_method` protobuf field: 0=none, 1=SE (darwin), 2=TPM (linux/windows).
- The custom circl fork (`cirl-custom/`) has `memguard` integration methods (`PackToLockedBuffer`, `UnmarshalBinaryFromLockedBuffer`) not present in upstream.
- SE uses P-256 ECIES directly on raw key bytes (no Argon2). TPM uses HMAC-combine + AES-256. Non-HSM uses Argon2id + AES-256-GCM.
- `PrivateKeyMLDSA` protobuf stores the encrypted key blob; `IK_mldsa` is excluded from `pqxdhPrivateBundle` (lives on filesystem).
- `EncryptPrivateKey` + `SerializePrivateKey` pattern used across X25519, ML-KEM, and ML-DSA.
- ML-DSA key store usa un parametro `bool` per decidere se salvare su disco — da sostituire con un tipo dedicato (es. `StorePolicy` enum) quando si sistema la funzione.

## Progress recap

| Area | Status | Details |
|------|--------|---------|
| ML-DSA keygen | ✅ Done | 3 security levels, memguard Enclave, sign/verify |
| ML-DSA encryption | ✅ Done | Argon2id + AES-256-GCM for non-HSM |
| SE (macOS) | ✅ Done | P-256 ECIES encrypt/decrypt, create/delete/search keys, needs codesign for test |
| TPM (linux/windows) | ✅ Done | Blob unseal + HMAC-combine + AES-256 |
| HSM dispatch | ✅ Done | `hsm_encrypt.go` + platform files, `WhichOS()`, `EncryptHSM()` |
| `storage.path.go` | ✅ Done | Auto-resolve project root via `go.mod` lookup |
| `PrivateCurveSet` / `PrivatekemSet` | ✅ Done | Struct for one-time private sets |
| `SetPair` struct | ✅ Done | Unified pair with `Private []byte` + `Public []byte` |
| `structures` subpackage | ✅ Done | Types in `pqxdh/structure/`, breaks circular import |
| `CreateCurveSet` / `CreatePQKEMSet` | ✅ Done | Return `SetPair` with msgpack-serialized bytes |
| `CreateCurveSets` / `CreateKEMsets` | ✅ Done | Loop over single-set functions, return `[]SetPair` |
| `CreateBundles` + cross-sign IK | ✅ Done | `CreateBundles` firma IK incrociata ML-DSA/X25519 |
| `FillMLDSA` / `FillXeddsa` refactor | ✅ Done | Ritornano enclave per firma immediata |
| `mldsa_keys.CreateKeys` refactor | ✅ Done | Ritorna anche raw enclave per signing |
| `database.SaveSets` | ✅ Done | Prende `[][]byte`, salva su bbolt |
| `GetBundleID` | ✅ Done | Esportata per uso da altri package |
| `InitializePQXDH` | ✅ Done | Crea bundle + sets + salva su DB, ritorna public bundle + public sets |
| Database salvataggio SPK + Last-resort | ✅ Done | `SavePrivateBundle` serializza e salva su bbolt |
| `CreateCurveSet` / `CreatePQKEMSet` refactor | ✅ Done | Ritornano `[]byte, []byte` invece di struct (marshal interno) |
| `CreateCurveSets` / `CreateKEMsets` refactor | ✅ Done | Ritornano `[][]byte, [][]byte` invece di `[]SetPair` |
| `SaveSets` signature | ✅ Done | Accetta `[][]byte` invece di `[]SetPair` |
| TLS 1.3 + PQ curves (X25519MLKEM768) | ✅ Done | `tls.Listen` / `tls.Dial` con CurvePreferences |
| TLS certificate Ed25519 (server) | ✅ Done | Autofirmato, PEM su disco |
| `transmission.ReadMsg` / `WriteMsg` | ✅ Done | 4B size + 32B SHA-256 checksum, 36B header, yamux-safe |
| `Connection` struct (client) | ✅ Done | yamux-based, SingleSession + Connection con Done pattern |
| `Wrapper` (yamux) | ✅ Done | yamux.Client + ConnectionManager |
| `Tor bootstrap` + dialer | ✅ Done | `InitializeTor` con cleanup, `CloseTor` |
| WriterManager (per-connection) | ❌ Da fare | Legge da Outgoing, serializza WriteMsg, valida messaggi |
| Dispatch / Reader Manager | ❌ Da fare | Cicla su Incoming, smista per tipo a handler |
| Messaggio format (tipo + payload) | ❌ Da fare | 1B tipo + payload + SHA-256 checksum |
| Riconnessione automatica | ❌ Da fare | Riaprire TLS + Connection se cade |
| Registrazione server (blind signature) | ❌ Da fare | Blind Schnorr su Ristretto255 |
| Autenticazione server con IK ML-DSA | ❌ Da fare | Firma messaggi con identity key |
| Invio public bundle + public sets al server | ❌ Da fare | Pubblicare `PublicBundle`, curve/KEM public sets |
| Test | ❌ Da fare | Test su connection, dispatch, transmission |
| Main di prova | ❌ Da fare | main.go che mette alla prova tutto |

## Agent rules

- **Always communicate in English.** Never write responses, comments, or messages in Italian.
- **Explain first, implement only after confirmed.** When the user asks about a design, approach, or code change, always explain the theory and options first. Never write or modify files until the user explicitly says to proceed ("si", "fallo", "implementa", "scrivi", "modifica"). Save this rule and follow it strictly.
- **Make only minimal changes.** Stick strictly to what the user asks. Do not create helper functions, refactor, or add new infrastructure. Only use existing functions in the codebase.
- **Use the same coding style as existing code.** Follow existing conventions: `module.action` naming, error wrapping with `apperr.Wrap`/`apperr.New`, `memguard` types for secrets, no superfluous comments, compact formatting.
- Do not rewrite entire files — make targeted edits.

## Architecture notes

- `apperr.Wrap` / `apperr.New` used by every internal package for error wrapping.
- All protobuf messages use proto3, generated into `proto_generated/`.
- TPM primary key is persistent in NV at handle `0x81000001`. First call is ~15s (RSA keygen), subsequent calls are ~0.4s (cached).
- SE uses `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM` for encryption.
- SE key is identified by label `"p2chat-secure-enclave-keys"` (TPM equivalent: `0x81000001`).

## Network architecture

### Client network stack

```
Application
  │
  ▼
WriterManager / Dispatch  ← ❌ da fare
  │
  ▼
SingleSession (yamux.Stream) — Listener + Writer goroutines
  ├─ Listener: ReadMessage → estrae Tag (1B) → Incoming chan
  └─ Writer:   Outgoing chan → WriteMessage
  │
  ▼
Connection (yamux.Session) — AcceptStream → NewSession
  ├─ pool ID circolare (NextID / ReleaseID)
  └─ CloseAllSessions / Close
  │
  ▼
Wrapper(yamux.Client) → ConnectionManager{Conn, Tor, GlobalOut}
  │
  ▼
TLS 1.3 (X25519MLKEM768 + X25519) — tls.Client(torConn, config)
  │
  ▼
Tor (SOCKS5 dialer) — InitializeTor → DialTor → EstablishTor
  │
  ▼
Server :8443
```

### Server network stack

```
Client TLS conn
  │
  ▼
handleConn → NewClient(conn)
  │
  ▼
yamux.Server → Connection{MasterSession, ActiveSessions, SessionHandler}
  │
  ▼
Connection.Listener — AcceptStream → NewSession(ID, stream)
  │
  ▼
Session{Listener, Writer, Dispatcher}
  ├─ Listener:  ReadMessage → Incoming
  ├─ Writer:    Outgoing → WriteMessage
  └─ Dispatcher: Incoming → Handler func(Session, []byte)
  │
  ▼
clientDispatch(msg[0]) — switch 0x01 → Registration (TODO)
```

### Key differences Client vs Server

| Aspect | Client | Server |
|--------|--------|--------|
| yamux role | `yamux.Client` | `yamux.Server` |
| Wrapper package | `wrapper.Wrapper()` — wraps yamux + Tor | `structs.NewClient()` — direct yamux.Server |
| ConnectionManager | ✅ Yes (conn, Tor, GlobalOut, Done) | ❌ No (Client.Conn is *Connection) |
| GlobalOut chan | ✅ Yes (per-connection) | ❌ No |
| Tor integration | ✅ TLS.go calls Tor, Wrapper stores Tor | ❌ Not needed |
| Session.Handler | ❌ No (managed by upper layer) | ✅ Yes (func pointer per dispatch) |
| Session.Tag | ✅ Extracts 1B tag from first message | ❌ Not implemented |
| Certificate gen | ✅ Duplicate of server code | ✅ Same function |
| TLS config | `InsecureSkipVerify: true` | Proper cert |

### Wire format

```
[4B big-endian length][32B SHA-256 checksum][payload bytes]
```

- `transmission.ReadMsg(conn)` — legge 4B header, poi 32B checksum, poi N byte payload, verifica checksum
- `transmission.WriteMsg(conn, data)` — calcola checksum SHA-256, crea header 36B ([4B size][32B hash]), scrive tutto
- `[36]byte` header sullo stack (zero alloc), payload fa `make([]byte, size)` sull'heap
- `io.ReadFull` per ogni lettura (non frammentato)
- `MaxMessageSize = 64 * 1024` (64KB)
- Supporto nativo per `yamux.Stream` (no deadlines interne, le gestisce yamux)

### Structs client

```
SingleSession:
  - ID uint32 (unico per connessione)
  - Tag string (letta dal primo byte payload)
  - Stream *yamux.Stream
  - Incoming/Outgoing/GlobalOut chan []byte
  - Done chan struct{}
  - goroutine Listener: ReadMessage → estrae Tag (1B) → Incoming
  - goroutine Writer: select { Outgoing → WriteMessage; Done → return }
  - Close() → close(Done)

Connection:
  - MasterSession *yamux.Session
  - ActiveSessions sync.Map (ID → *SingleSession)
  - GlobalOut chan<- []byte
  - Done chan struct{}
  - NextID() / ReleaseID() — pool circolare ID
  - Listener(): loop AcceptStream → NewSession
  - ReleaseSession(session): LoadAndDelete + ReleaseID + Close
  - CloseAllSessions()
  - Close() → close(Done) + MasterSession.Close() + CloseAllSessions()

ConnectionManager:
  - Conn *Connection
  - Tor *tor.Tor
  - GlobalOut chan<- []byte
  - Done chan struct{}
```

### Structs server

```
Client:
  - ID []byte
  - Authed bool
  - Conn *Connection

Session:
  - ID uint32
  - Stream *yamux.Stream
  - Incoming/Outgoing chan []byte
  - Once sync.Once
  - Done chan struct{}
  - Handler func(*Session, []byte)

Connection:
  - MasterSession *yamux.Session
  - ActiveSessions sync.Map
  - nextID / freeIDs / mu
  - Once / Done
  - SessionHandler func(*Session, []byte)
```

### Messaggio types

| Tipo | Nome | Mittente | Destinatario | Payload |
|------|------|----------|-------------|---------|
| `0x01` | REGISTER_REQ | Client | Server | UserID (32B) + PublicBundle |
| `0x02` | REGISTER_RES | Server | Client | OK / ERR |
| `0x03` | BUNDLE_REQUEST | Client | Server | TargetUserID |
| `0x04` | BUNDLE_RESPONSE | Server | Client | TargetUserID + PublicBundle |
| `0x05` | DUMMY_REQUEST | Client | Server | Random ID (ORAM) |
| `0x06` | MAILBOX_PUT | Client | Server | MailboxID + Ciphertext + TAG |
| `0x07` | MAILBOX_GET | Client | Server | MailboxID |
| `0x08` | MAILBOX_CONTENTS | Server | Client | []{Ciphertext + TAG} |
| `0x09` | FRIEND_REQUEST | Client→S | Mailbox | Messaggio cifrato |
| `0x0A` | SESSION_INIT | Client | Client | PQXDH initial message |
| `0x0B` | CHAT_MESSAGE | Client | Client (P2P) | Ratchet header + ciphertext |
| `0x0C` | IP_SHARE | Client | Client | IP cifrato |

### Next steps (ordine logico)

1. `transmission/msg.go` — ReadMsg + WriteMsg
2. `TLS/TLS.go` — Connection struct + readerLoop + writeLoop + Close
3. `main.go` — test Connection con server esistente
4. Dispatch / Manager — ciclo su Incoming, handler routing
5. WriterManager — per-connessione, serializza scritture
6. Riconnessione — riapre TLS + Connection se cade
7. Registrazione server — blind Schnorr su Ristretto255 + publish bundle
8. Autenticazione — firma messaggi con IK ML-DSA
9. Ottimizzazione pacchetti — compressione, single-key request

## Server progress (cmd/server)

| Area | Status | Details |
|------|--------|---------|
| TLS 1.3 listener + PQ curves | ✅ Done | `connection.go`: `tls.Listen` su `:8443`, `X25519MLKEM768` |
| Certificato Ed25519 autofirmato | ✅ Done | `certificate.go`: generazione + salvataggio PEM con memguard |
| Yamux multiplexing | ✅ Done | `structs.go`: Client, Session, Connection con sync.Map pool ID |
| `Session.Listener` / `Session.Writer` | ✅ Done | `session_methods.go`: ReadMessage/WriteMessage loop |
| `Connection.Listener` (accept stream) | ✅ Done | `connection_methods.go`: accetta stream yamux → NewSession |
| `NewClient` + `clientDispatch` | ✅ Done | `client_methods.go`: yamux.Server, switch 0x01 |
| `dispatcher/registration.go` | 🔶 Scheletro | Funzione vuota, nessuna logica |
| `pinned_keys/initialization.go` | ✅ Done | ML-DSA-87 keys per EKM layer |
| `network/tls/tls.go` | 🗑️ Obsoleto | Duplicato non integrato (package name conflitto) |
| Database server (BadgerDB) | ❌ Da fare | Menzionato in recap.md |
| Blind signature (Ristretto255) | ❌ Da fare | Nessuna implementazione |
| Mailbox system | ❌ Da fare | Cifratura + deposito offline |
| Bundle store + distribution | ❌ Da fare | Ricevere, memorizzare bundle pubblici |
| EKM layer integration | ❌ Da fare | Firma ML-DSA transcript hash |
| Autenticazione client IK ML-DSA | ❌ Da fare | Verifica firma messaggi |
| Rate limiting / PoW | ❌ Da fare | Protezione DDoS |

## TODO prossima sessione

### WriterManager / Dispatch / Messaggio format
- WriterManager (per-connessione): serializza WriteMsg, valida messaggi
- Dispatch/ReaderManager: ciclo su Incoming, smista per tipo
- Formato messaggio: 1B tipo + payload

### Client logic
- iniziare logica inizializzazione client (connessione, autenticazione)
- simulare connessione post-implementazione
- registration flow + blind signature Ristretto255

### Server
- Implementare `Registration` handler (dispatcher/registration.go)
- Implementare BadgerDB per storage utenti/bundle
- Integrare EKM layer con ML-DSA pinned keys
- Buildare Dockerfile server (docker-compose.yml punta a `./server` non esistente)
- Eliminare o integrare `network/tls/tls.go` duplicato

### Riconnessione automatica
- Riaprire TLS + Connection se cade

### Test
- Test su connection, dispatch, transmission, tor
- Main di prova (main.go)

## Agent rules (Italian)

- **Parla in italiano** quando l'utente parla in italiano.
- **Prima spiega, implementa solo dopo conferma.** Quando l'utente chiede di design, approccio o modifiche, spiega prima teoria e opzioni. Non scrivere o modificare file finché l'utente non dice esplicitamente di procedere ("si", "fallo", "implementa", "scrivi", "modifica").
- **Modifiche minime.** Attieniti strettamente a ciò che chiede l'utente. Non creare funzioni helper, refactoring o nuova infrastruttura. Usa solo funzioni esistenti.
- **Stesso stile del codice esistente.** `module.action` naming, error wrapping con `apperr.Wrap`/`apperr.New`, `memguard` per segreti, nessun commento superfluo, formatting compatto.
- **Non riscrivere file interi** — fai edit mirati.