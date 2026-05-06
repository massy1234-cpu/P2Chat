# TPM in Go — Rilevazione e Gestione Cross-Platform

---

## 1. Rilevare il Sistema Operativo in Go

Go espone il SO corrente tramite la costante `runtime.GOOS`, disponibile a runtime e anche come build tag.

```go
package main

import (
    "fmt"
    "runtime"
)

func detectOS() string {
    switch runtime.GOOS {
    case "linux":
        return "Linux"
    case "windows":
        return "Windows"
    case "darwin":
        return "macOS"
    case "freebsd":
        return "FreeBSD"
    default:
        return "Unknown: " + runtime.GOOS
    }
}
```

### Valori possibili di `runtime.GOOS`

| Valore      | Sistema Operativo     |
|-------------|----------------------|
| `linux`     | Linux                |
| `windows`   | Windows              |
| `darwin`    | macOS                |
| `freebsd`   | FreeBSD              |
| `openbsd`   | OpenBSD              |
| `android`   | Android              |
| `ios`       | iOS                  |

### Build tag per file specifici per OS

Puoi avere file Go compilati solo su certi OS usando i build tag:

```go
//go:build linux
// +build linux

package keystore

// Questo file viene compilato SOLO su Linux
```

```go
//go:build windows
// +build windows

package keystore

// Questo file viene compilato SOLO su Windows
```

```go
//go:build darwin
// +build darwin

package keystore

// Questo file viene compilato SOLO su macOS
```

---

## 2. Rilevare la Presenza del TPM per SO

### Linux

Su Linux il TPM è esposto come device file. Esistono due interfacce:

| Device         | Descrizione                              |
|----------------|------------------------------------------|
| `/dev/tpm0`    | Accesso diretto raw (richiede root)      |
| `/dev/tpmrm0`  | Resource Manager kernel (raccomandato)   |

```go
//go:build linux

package tpm

import (
    "os"
)

func IsTPMAvailable() bool {
    // Prova prima il resource manager (preferito)
    if _, err := os.Stat("/dev/tpmrm0"); err == nil {
        return true
    }
    // Fallback al device raw
    if _, err := os.Stat("/dev/tpm0"); err == nil {
        return true
    }
    return false
}

func GetTPMDevice() string {
    if _, err := os.Stat("/dev/tpmrm0"); err == nil {
        return "/dev/tpmrm0"
    }
    if _, err := os.Stat("/dev/tpm0"); err == nil {
        return "/dev/tpm0"
    }
    return ""
}
```

Puoi anche verificare la versione TPM leggendo sysfs:

```go
//go:build linux

package tpm

import (
    "os"
    "strings"
)

func GetTPMVersion() string {
    // TPM 2.0
    data, err := os.ReadFile("/sys/class/tpm/tpm0/tpm_version_major")
    if err == nil {
        version := strings.TrimSpace(string(data))
        if version == "2" {
            return "2.0"
        }
        return "1.2"
    }
    return "unknown"
}
```

---

### Windows

Su Windows il TPM è accessibile tramite WMI oppure tramite le API NCrypt/Platform Security.
Con Go puoi interrogare WMI usando `golang.org/x/sys/windows`:

```go
//go:build windows

package tpm

import (
    "golang.org/x/sys/windows/registry"
)

func IsTPMAvailable() bool {
    // Controlla il registro di sistema
    key, err := registry.OpenKey(
        registry.LOCAL_MACHINE,
        `SYSTEM\CurrentControlSet\Services\TPM`,
        registry.QUERY_VALUE,
    )
    if err != nil {
        return false
    }
    defer key.Close()

    // Verifica che il servizio TPM sia attivo
    val, _, err := key.GetIntegerValue("Start")
    if err != nil {
        return false
    }
    // Start = 3 significa manuale/disponibile, != 4 (disabled)
    return val != 4
}

func GetTPMVersion() string {
    key, err := registry.OpenKey(
        registry.LOCAL_MACHINE,
        `SYSTEM\CurrentControlSet\Control\IntegrityServices`,
        registry.QUERY_VALUE,
    )
    if err != nil {
        return "unknown"
    }
    defer key.Close()

    val, _, err := key.GetStringValue("TPMVersion")
    if err != nil {
        return "unknown"
    }
    return val
}
```

> **Nota:** Su Windows moderno (10/11) il TPM è quasi sempre presente come **fTPM** (firmware TPM integrato nel SoC AMD/Intel), non come chip discreto.

---

### macOS

macOS **non ha TPM standard**. Ha il **Secure Enclave** (su Apple Silicon e T2), ma l'API è completamente diversa e non compatibile con le API TPM 2.0.

```go
//go:build darwin

package tpm

import (
    "os/exec"
    "strings"
)

func IsTPMAvailable() bool {
    // macOS non ha TPM — ha Secure Enclave
    return false
}

func IsSecureEnclaveAvailable() bool {
    // Verifica presenza Secure Enclave tramite system_profiler
    out, err := exec.Command(
        "system_profiler", "SPiBridgeDataType",
    ).Output()
    if err != nil {
        return false
    }
    return strings.Contains(string(out), "Apple T") ||
           strings.Contains(string(out), "Secure Enclave")
}
```

---

## 3. Gestire il TPM in Go per SO

### Libreria consigliata: `google/go-tpm`

```bash
go get github.com/google/go-tpm/tpm2
go get github.com/google/go-tpm/tpm2/transport
```

Funziona su **Linux e Windows**. Su macOS devi usare un approccio diverso (vedi sotto).

---

### Interfaccia comune (cross-platform)

Definisci prima l'interfaccia, poi implementa per ogni OS:

```go
// keystore/interface.go
package keystore

// HardwareKeyStore è l'interfaccia unica per tutti i backend
type HardwareKeyStore interface {
    // Verifica se l'hardware è disponibile
    IsAvailable() bool

    // Genera e persiste una KEK nell'hardware
    // Restituisce un blob da salvare su disco
    GenerateKEK(keyID string) (blob []byte, err error)

    // Usa la KEK per cifrare plaintext (es. una chiave MLDSA)
    Encrypt(blob []byte, plaintext []byte) (ciphertext []byte, err error)

    // Usa la KEK per decifrare
    Decrypt(blob []byte, ciphertext []byte) (plaintext []byte, err error)

    // Nome del backend (per logging)
    Name() string
}

// NewKeyStore seleziona automaticamente il backend migliore disponibile
func NewKeyStore() HardwareKeyStore {
    candidates := []HardwareKeyStore{
        newTPMKeyStore(),       // Linux / Windows
        newSEKeyStore(),        // macOS Secure Enclave
        newSoftwareKeyStore(),  // fallback software
    }
    for _, ks := range candidates {
        if ks.IsAvailable() {
            return ks
        }
    }
    // Software fallback è sempre disponibile
    return newSoftwareKeyStore()
}
```

---

### Backend Linux — TPM 2.0

```go
//go:build linux

// keystore/tpm_linux.go
package keystore

import (
    "crypto/rand"
    "io"
    "os"

    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
)

type tpmKeyStore struct {
    device string
}

func newTPMKeyStore() HardwareKeyStore {
    device := ""
    if _, err := os.Stat("/dev/tpmrm0"); err == nil {
        device = "/dev/tpmrm0"
    } else if _, err := os.Stat("/dev/tpm0"); err == nil {
        device = "/dev/tpm0"
    }
    return &tpmKeyStore{device: device}
}

func (t *tpmKeyStore) Name() string { return "TPM 2.0 (Linux)" }

func (t *tpmKeyStore) IsAvailable() bool {
    return t.device != ""
}

func (t *tpmKeyStore) openTPM() (transport.TPMCloser, error) {
    return transport.OpenTPM(t.device)
}

// GenerateKEK genera una chiave AES-256 dentro il TPM
// Restituisce un "key blob" cifrato dal TPM stesso da salvare su disco
func (t *tpmKeyStore) GenerateKEK(keyID string) ([]byte, error) {
    tpm, err := t.openTPM()
    if err != nil {
        return nil, err
    }
    defer tpm.Close()

    // Crea la chiave primaria (parent key) nel TPM
    primary, err := tpm2.CreatePrimary{
        PrimaryHandle: tpm2.TPMRHOwner,
        InPublic: tpm2.New2B(tpm2.TPMTPublic{
            Type:    tpm2.TPMAlgSymCipher,
            NameAlg: tpm2.TPMAlgSHA256,
            ObjectAttributes: tpm2.TPMAObject{
                FixedTPM:            true,
                FixedParent:         true,
                SensitiveDataOrigin: true,
                UserWithAuth:        true,
                Decrypt:             true,
            },
            Parameters: tpm2.NewTPMUPublicParms(
                tpm2.TPMAlgSymCipher,
                &tpm2.TPMSSymCipherParms{
                    Sym: tpm2.TPMTSymDef{
                        Algorithm: tpm2.TPMAlgAES,
                        KeyBits:   tpm2.NewTPMIAESKeyBits(256),
                        Mode:      tpm2.NewTPMISymMode(tpm2.TPMAlgCFB),
                    },
                },
            ),
        }),
    }.Execute(tpm)
    if err != nil {
        return nil, err
    }

    // Serializza il context della chiave come blob
    ctx, err := tpm2.ContextSave{
        SaveHandle: primary.ObjectHandle,
    }.Execute(tpm)
    if err != nil {
        return nil, err
    }

    // Flush l'handle dalla memoria del TPM
    tpm2.FlushContext{FlushHandle: primary.ObjectHandle}.Execute(tpm)

    return tpm2.Marshal(ctx.Context), nil
}

// Encrypt cifra plaintext usando la chiave nel TPM
func (t *tpmKeyStore) Encrypt(blob []byte, plaintext []byte) ([]byte, error) {
    tpm, err := t.openTPM()
    if err != nil {
        return nil, err
    }
    defer tpm.Close()

    // Ricarica la chiave dal blob
    var ctx tpm2.TPMSContext
    if err := tpm2.Unmarshal(blob, &ctx); err != nil {
        return nil, err
    }

    loaded, err := tpm2.ContextLoad{Context: ctx}.Execute(tpm)
    if err != nil {
        return nil, err
    }
    defer tpm2.FlushContext{FlushHandle: loaded.LoadedHandle}.Execute(tpm)

    // Genera IV random
    iv := make([]byte, 16)
    if _, err := io.ReadFull(rand.Reader, iv); err != nil {
        return nil, err
    }

    encrypted, err := tpm2.EncryptDecrypt2{
        KeyHandle: tpm2.AuthHandle{Handle: loaded.LoadedHandle},
        Message:   tpm2.TPM2BMaxBuffer{Buffer: plaintext},
        Decrypt:   tpm2.NewTPMIYesNo(false),
        IV:        tpm2.TPM2BIV{Buffer: iv},
    }.Execute(tpm)
    if err != nil {
        return nil, err
    }

    // Restituisce IV + ciphertext
    result := make([]byte, len(iv)+len(encrypted.OutData.Buffer))
    copy(result, iv)
    copy(result[len(iv):], encrypted.OutData.Buffer)
    return result, nil
}

// Decrypt decifra usando la chiave nel TPM
func (t *tpmKeyStore) Decrypt(blob []byte, ciphertext []byte) ([]byte, error) {
    tpm, err := t.openTPM()
    if err != nil {
        return nil, err
    }
    defer tpm.Close()

    var ctx tpm2.TPMSContext
    if err := tpm2.Unmarshal(blob, &ctx); err != nil {
        return nil, err
    }

    loaded, err := tpm2.ContextLoad{Context: ctx}.Execute(tpm)
    if err != nil {
        return nil, err
    }
    defer tpm2.FlushContext{FlushHandle: loaded.LoadedHandle}.Execute(tpm)

    // Estrae IV dal ciphertext
    iv := ciphertext[:16]
    data := ciphertext[16:]

    decrypted, err := tpm2.EncryptDecrypt2{
        KeyHandle: tpm2.AuthHandle{Handle: loaded.LoadedHandle},
        Message:   tpm2.TPM2BMaxBuffer{Buffer: data},
        Decrypt:   tpm2.NewTPMIYesNo(true),
        IV:        tpm2.TPM2BIV{Buffer: iv},
    }.Execute(tpm)
    if err != nil {
        return nil, err
    }

    return decrypted.OutData.Buffer, nil
}
```

---

### Backend Windows — TPM 2.0

Su Windows `go-tpm` usa automaticamente le API Windows invece di `/dev/tpmrm0`.
La differenza è solo nell'apertura del device:

```go
//go:build windows

// keystore/tpm_windows.go
package keystore

import (
    "github.com/google/go-tpm/tpm2/transport"
)

type tpmKeyStore struct{}

func newTPMKeyStore() HardwareKeyStore {
    return &tpmKeyStore{}
}

func (t *tpmKeyStore) Name() string { return "TPM 2.0 (Windows)" }

func (t *tpmKeyStore) IsAvailable() bool {
    // Su Windows tenta apertura per verificare disponibilità
    tpm, err := transport.OpenTPM()
    if err != nil {
        return false
    }
    tpm.Close()
    return true
}

func (t *tpmKeyStore) openTPM() (transport.TPMCloser, error) {
    // Su Windows non serve specificare il device
    // go-tpm usa automaticamente il TPM Windows
    return transport.OpenTPM()
}

// GenerateKEK, Encrypt, Decrypt — stessa implementazione di Linux
// Puoi mettere la logica in un file condiviso tpm_common.go
// con build tag: //go:build linux || windows
```

> La logica di `GenerateKEK`, `Encrypt`, `Decrypt` è **identica** su Linux e Windows una volta aperto il TPM. Puoi fattorizzarla in un file `tpm_common.go` con build tag `linux || windows`.

---

### Backend macOS — Secure Enclave

Su macOS devi usare `CGo` per chiamare `Security.framework`:

```go
//go:build darwin

// keystore/secure_enclave_darwin.go
package keystore

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

// Genera una chiave EC nel Secure Enclave
// Restituisce 0 se successo
int generateSEKey(const char* keyID) {
    CFStringRef label = CFStringCreateWithCString(
        NULL, keyID, kCFStringEncodingUTF8
    );

    CFMutableDictionaryRef params = CFDictionaryCreateMutable(
        NULL, 0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFDictionarySetValue(params, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(params, kSecAttrKeySizeInBits, CFSTR("256"));
    CFDictionarySetValue(params, kSecAttrLabel, label);
    CFDictionarySetValue(params, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(params, kSecAttrIsPermanent, kCFBooleanTrue);

    SecKeyRef privateKey = NULL;
    CFErrorRef error = NULL;
    privateKey = SecKeyCreateRandomKey(params, &error);

    CFRelease(params);
    CFRelease(label);

    if (error != NULL) {
        CFRelease(error);
        return -1;
    }
    if (privateKey) CFRelease(privateKey);
    return 0;
}
*/
import "C"

type seKeyStore struct {
    available bool
}

func newSEKeyStore() HardwareKeyStore {
    return &seKeyStore{available: isSecureEnclavePresent()}
}

func (s *seKeyStore) Name() string        { return "Secure Enclave (macOS)" }
func (s *seKeyStore) IsAvailable() bool   { return s.available }

func isSecureEnclavePresent() bool {
    // Apple Silicon e Mac con chip T2 hanno il Secure Enclave
    // Tenta di creare una chiave temporanea per verificare
    result := C.generateSEKey(C.CString("__test_probe__"))
    return result == 0
}

// Nota: su macOS la cifratura simmetrica tramite SE è più complessa.
// Il pattern tipico è:
//   1. SE genera keypair EC (privkey non esce mai)
//   2. Usi ECDH per derivare una KEK
//   3. Con la KEK cifri i file con AES-256-GCM in Go puro
```

> **Alternativa più pratica su macOS:** usa la libreria [`keychain`](https://github.com/keybase/go-keychain) che wrappa il Keychain di macOS (protetto dal Secure Enclave) senza CGo complesso.

```bash
go get github.com/keybase/go-keychain
```

```go
//go:build darwin

package keystore

import keychain "github.com/keybase/go-keychain"

// Salva la KEK nel Keychain di macOS (protetto da SE)
func saveKEKToKeychain(keyID string, kek []byte) error {
    item := keychain.NewItem()
    item.SetSecClass(keychain.SecClassGenericPassword)
    item.SetService("myapp.keystore")
    item.SetAccount(keyID)
    item.SetData(kek)
    item.SetAccessible(keychain.AccessibleAfterFirstUnlockThisDeviceOnly)
    return keychain.AddItem(item)
}

// Carica la KEK dal Keychain
func loadKEKFromKeychain(keyID string) ([]byte, error) {
    query := keychain.NewItem()
    query.SetSecClass(keychain.SecClassGenericPassword)
    query.SetService("myapp.keystore")
    query.SetAccount(keyID)
    query.SetMatchLimit(keychain.MatchLimitOne)
    query.SetReturnData(true)

    results, err := keychain.QueryItem(query)
    if err != nil || len(results) == 0 {
        return nil, err
    }
    return results[0].Data, nil
}
```

---

### Fallback Software (tutti gli OS)

Quando né TPM né Secure Enclave sono disponibili:

```go
// keystore/software_fallback.go
// (nessun build tag — compila su tutti gli OS)

package keystore

import (
    "crypto/rand"
    "crypto/sha256"
    "errors"
    "io"
    "os"

    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/chacha20poly1305"
)

type softwareKeyStore struct {
    secretPath string // path al file con il segreto master
}

func newSoftwareKeyStore() HardwareKeyStore {
    return &softwareKeyStore{secretPath: "/etc/myapp/master.secret"}
}

func (s *softwareKeyStore) Name() string      { return "Software (no hardware)" }
func (s *softwareKeyStore) IsAvailable() bool { return true }

// Deriva la KEK da un segreto su disco + KDF lento
func (s *softwareKeyStore) deriveKEK(salt []byte) ([]byte, error) {
    secret, err := os.ReadFile(s.secretPath)
    if err != nil {
        // Genera un segreto nuovo se non esiste
        secret = make([]byte, 32)
        if _, err := io.ReadFull(rand.Reader, secret); err != nil {
            return nil, err
        }
        os.WriteFile(s.secretPath, secret, 0600)
    }

    // Argon2id come KDF — lento contro brute force
    kek := argon2.IDKey(secret, salt, 3, 64*1024, 2, 32)
    return kek, nil
}

func (s *softwareKeyStore) GenerateKEK(keyID string) ([]byte, error) {
    salt := make([]byte, 32)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, err
    }
    // Il "blob" nel fallback software è semplicemente il salt
    return salt, nil
}

func (s *softwareKeyStore) Encrypt(blob []byte, plaintext []byte) ([]byte, error) {
    kek, err := s.deriveKEK(blob)
    if err != nil {
        return nil, err
    }
    defer zeroBytes(kek)

    aead, err := chacha20poly1305.NewX(kek)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, aead.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    ciphertext := aead.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}

func (s *softwareKeyStore) Decrypt(blob []byte, ciphertext []byte) ([]byte, error) {
    kek, err := s.deriveKEK(blob)
    if err != nil {
        return nil, err
    }
    defer zeroBytes(kek)

    aead, err := chacha20poly1305.NewX(kek)
    if err != nil {
        return nil, err
    }

    nonceSize := aead.NonceSize()
    if len(ciphertext) < nonceSize {
        return nil, errors.New("ciphertext troppo corto")
    }

    nonce, data := ciphertext[:nonceSize], ciphertext[nonceSize:]
    return aead.Open(nil, nonce, data, nil)
}

// zeroBytes azzera un slice in memoria
func zeroBytes(b []byte) {
    for i := range b {
        b[i] = 0
    }
}

// Evita che il compilatore ottimizzi via lo zeroing
var _ = sha256.New
```

---

## 4. Struttura del Progetto Consigliata

```
/keystore
    interface.go              ← HardwareKeyStore interface + NewKeyStore()
    tpm_common.go             ← logica TPM condivisa (build: linux || windows)
    tpm_linux.go              ← apertura /dev/tpmrm0 (build: linux)
    tpm_windows.go            ← apertura Windows TPM API (build: windows)
    secure_enclave_darwin.go  ← Secure Enclave via CGo (build: darwin)
    software_fallback.go      ← fallback Argon2id (tutti gli OS)

/keys
    mldsa_identity.key        ← MLDSA privkey cifrata con KEK
    hmac_session.key          ← HMAC key cifrata con KEK
    kek_<keyID>.blob          ← blob TPM/SE da passare a Decrypt
```

---

## 5. Tabella Riepilogativa per SO

| OS      | Hardware disponibile     | Libreria Go                    | Fallback              |
|---------|--------------------------|--------------------------------|-----------------------|
| Linux   | TPM 2.0 (`/dev/tpmrm0`) | `google/go-tpm`                | Software + Argon2id   |
| Windows | fTPM / TPM 2.0 discreto  | `google/go-tpm`                | Software + Argon2id   |
| macOS   | Secure Enclave (T2/M*)   | `keybase/go-keychain` + CGo    | Software + Argon2id   |
| Altri   | Nessuno                  | —                              | Software + Argon2id   |

---

## 6. Dipendenze Go da aggiungere al `go.mod`

```bash
# TPM 2.0 (Linux + Windows)
go get github.com/google/go-tpm/tpm2
go get github.com/google/go-tpm/tpm2/transport

# Windows registry (per rilevazione TPM)
go get golang.org/x/sys/windows/registry

# macOS Keychain
go get github.com/keybase/go-keychain

# KDF per fallback software
go get golang.org/x/crypto/argon2
go get golang.org/x/crypto/chacha20poly1305
```