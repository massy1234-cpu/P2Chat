# go-tpm: Legacy v0.3.x vs Moderna v0.9.x

---

## 1. Il problema: due API incompatibili

La libreria `github.com/google/go-tpm` ha **cambiato completamente** l'API tra la versione v0.3.x e la v0.9.x. Le due versioni usano gli stessi nomi di package (`tpm2`) ma tipi e funzioni completamente diversi — codice scritto per una versione non compila con l'altra.

| Versione | Stato         | Filosofia                              |
|----------|---------------|----------------------------------------|
| v0.3.x   | Deprecata     | Funzioni Go con argomenti posizionali  |
| v0.9.x   | Attiva        | Command structs 1:1 con specifica TCG  |

---

## 2. Aprire la connessione al TPM

### Legacy v0.3.x

La connessione restituisce un `io.ReadWriteCloser` — il TPM è trattato come un file da cui leggere e scrivere byte.

```go
import "github.com/google/go-tpm/tpm2"

// Apre /dev/tpmrm0 e restituisce io.ReadWriteCloser
tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
if err != nil {
    return err
}
defer tpm.Close()
```

### Moderna v0.9.x

La connessione restituisce `transport.TPMCloser`, un'interfaccia che astrae il protocollo di comunicazione con il TPM (sia su Linux che Windows).

```go
import "github.com/google/go-tpm/tpm2/transport"

// Apre /dev/tpmrm0 e restituisce transport.TPMCloser
tpm, err := transport.OpenTPM("/dev/tpmrm0")
if err != nil {
    return err
}
defer tpm.Close()
```

> Su Windows non si specifica il device: `transport.OpenTPM()` usa automaticamente le API TBS (TPM Base Services) di Windows.

---

## 3. Creare una chiave primaria (CreatePrimary)

La chiave primaria è la radice della gerarchia del TPM. È un nodo padre che "sigilla" e protegge tutte le chiavi figlie. Non esce mai dal TPM.

### Legacy v0.3.x

```go
// Il template descrive la chiave che vogliamo creare
primaryTemplate := tpm2.Public{
    Type:       tpm2.AlgRSA,
    NameAlg:    tpm2.AlgSHA256,
    Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
                tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
                tpm2.FlagRestricted | tpm2.FlagDecrypt,
    RSAParameters: &tpm2.RSAParams{
        Symmetric: &tpm2.SymScheme{
            Alg:     tpm2.AlgAES,
            KeyBits: 128,
        },
        KeyBits: 2048,
    },
}

// Ritorna: (tpmutil.Handle, crypto.PublicKey, error)
handle, pubKey, err := tpm2.CreatePrimary(
    tpm,                 // io.ReadWriter — la connessione aperta
    tpm2.HandleOwner,    // gerarchia: TPM_RH_OWNER
    tpm2.PCRSelection{}, // nessun PCR binding
    "",                  // auth della gerarchia (vuoto = nessuna password)
    "",                  // auth della chiave (vuoto = nessuna password)
    primaryTemplate,     // template tpm2.Public{}
)
if err != nil {
    return err
}
defer tpm2.FlushContext(tpm, handle)

// pubKey è di tipo crypto.PublicKey (interfaccia generica)
rsaKey := pubKey.(*rsa.PublicKey)
```

### Moderna v0.9.x

```go
import "github.com/google/go-tpm/tpm2"

// resp is a struct *tpm2.CreatePrimaryResponse
resp, err := tpm2.CreatePrimary{
    
    // La gerarchia in cui creare la chiave ( in questo caso owner )
    PrimaryHandle: tpm2.TPMRHOwner,

    // Il template della chiave avvolto nel container TPM2B.
    // New2B serializza la struct in formato binario TPM (2 byte lunghezza + payload)
    // — obbligatorio per la trasmissione al chip.
    InPublic: tpm2.New2B(tpm2.TPMTPublic{

        // Algoritmo della chiave
        Type: tpm2.TPMAlgRSA,

        // Algoritmo hash usato per calcolare il Name dell'oggetto.
        // Il Name è l'identità criptografica della chiave
        NameAlg: tpm2.TPMAlgSHA256,

        // Attributi dell'oggetto — ogni campo è un bit della specifica TCG.
        ObjectAttributes: tpm2.TPMAObject{
            
            // La chiave non può essere duplicata su un altro TPM.
            FixedTPM: true,

            // Il parent non può cambiare — la chiave è ancorata permanentemente
            FixedParent: true,

            // Il materiale privato (chiave RSA) è stato generato internamente
            SensitiveDataOrigin: true,

            // Le operazioni USER ( uso normale della chiave ) possono essere autorizzate con password
            UserWithAuth: true,

            // usata per decifrare solo le chiavi da lei cifrate e non qualsiasi in maniera arbritaria
            Restricted: true,

            // può aprire i blob delle chiavi figlie.
            Decrypt: true,
        },

        // Parametri specifici per RSA
        Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{

            // Per una storage key restricted, definisce l'algoritmo simmetrico e li unifica in una sola struct
            Symmetric: tpm2.TPMTSymDefObject{
                Algorithm: tpm2.TPMAlgAES,
                KeyBits: tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
                Mode: tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
            },

            // Per una storage key (Restricted + Decrypt), lo scheme RSA deve essere
            // NULL — la chiave non firma né fa operazioni asimmetriche dirette,
            // serve solo per l'unwrap dei blob figli.
            Scheme: tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},

            // Dimensione in bit della chiave RSA.
            KeyBits: 2048,
        }),
    }),
// Execute serializza il comando, lo invia al transport ( canale di comunicazione tra programma GO e chip TPM ) e aspetta la risposta.
}.Execute(tpm)
if err != nil {
    return err
}
defer tpm2.FlushContext{FlushHandle: resp.ObjectHandle}.Execute(tpm)

// Il response è una struct tipizzata con tutti i campi della specifica TCG.
primaryHandle := resp.ObjectHandle // TPMHandle — handle transiente in memoria TPM
primaryName   := resp.Name         // TPM2BName  — identità criptografica, usala in NamedHandle
primaryPub    := resp.OutPublic    // TPM2BPublic — chiave pubblica RSA
```

---

## 4. Creare una chiave figlia (Create)

La chiave figlia è creata dentro il TPM, cifrata dalla chiave primaria, e restituita come **blob** che puoi salvare su disco. Senza la chiave primaria (che resta nel TPM) il blob è inutilizzabile.

### Legacy v0.3.x

```go
hmacTemplate := tpm2.Public{
    Type:       tpm2.AlgKeyedHash,
    NameAlg:    tpm2.AlgSHA256,
    Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
                tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
                tpm2.FlagSign,
    KeyedHashParameters: &tpm2.KeyedHashParams{
        Alg:  tpm2.AlgHMAC,
        Hash: tpm2.AlgSHA256,
    },
}

// Ritorna: (privateBlob []byte, publicBlob []byte, error)
private, public, err := tpm2.Create(
    tpm,
    handle,              // handle della chiave primaria
    tpm2.PCRSelection{},
    "",
    "",
    hmacTemplate,
)
if err != nil {
    return err
}
// private e public sono blob binari grezzi da salvare su disco
```

### Moderna v0.9.x

```go
// NamedHandle: serve sia l'handle che il Name della chiave padre
// Il Name è il digest criptografico dell'oggetto — lega la figlia alla madre
createResp, err := tpm2.Create{
    ParentHandle: tpm2.NamedHandle{
        Handle: resp.ObjectHandle,
        Name:   resp.Name,
    },
    InPublic: tpm2.New2B(tpm2.TPMTPublic{
        Type:    tpm2.TPMAlgKeyedHash,
        NameAlg: tpm2.TPMAlgSHA256,
        ObjectAttributes: tpm2.TPMAObject{
            FixedTPM:            true,
            FixedParent:         true,
            SensitiveDataOrigin: true,
            UserWithAuth:        true,
            SignEncrypt:         true, // in v0.9.x "Sign" si chiama "SignEncrypt"
        },
        Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
            Scheme: tpm2.TPMTKeyedHashScheme{
                Scheme: tpm2.TPMAlgHMAC,
                Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{
                    HashAlg: tpm2.TPMAlgSHA256,
                }),
            },
        }),
    }),
}.Execute(tpm)
if err != nil {
    return err
}

// Il response ha campi tipizzati invece di []byte grezzi
privateBlob := createResp.OutPrivate // TPM2BPrivate
publicBlob  := createResp.OutPublic  // TPM2BPublic
```

---

## 5. Flush dell'handle

Quando hai finito con un handle transiente, devi liberarlo dalla memoria del TPM. Il TPM ha una memoria limitata per gli handle transienti.

### Legacy v0.3.x

```go
// Funzione con 2 argomenti
tpm2.FlushContext(tpm, handle)
```

### Moderna v0.9.x

```go
// Struct + Execute — coerente con tutti gli altri comandi
tpm2.FlushContext{FlushHandle: handle}.Execute(tpm)

// Con defer (ignora l'errore — è best practice per il flush)
defer tpm2.FlushContext{FlushHandle: handle}.Execute(tpm) //nolint:errcheck
```

---

## 6. Il sistema dei tipi a confronto

### Corrispondenza tra specifica TCG, v0.3.x e v0.9.x

| Specifica TCG          | v0.3.x                    | v0.9.x                      |
|------------------------|---------------------------|-----------------------------|
| `TPMT_PUBLIC`          | `tpm2.Public`             | `tpm2.TPMTPublic`           |
| `TPM2B_PUBLIC`         | (inline in `Public`)      | `tpm2.TPM2BPublic`          |
| `TPMA_OBJECT`          | bitmask `uint32`          | `tpm2.TPMAObject` (struct)  |
| `TPM_ALG_RSA`          | `tpm2.AlgRSA`             | `tpm2.TPMAlgRSA`            |
| `TPM_ALG_SHA256`       | `tpm2.AlgSHA256`          | `tpm2.TPMAlgSHA256`         |
| `TPM_ALG_AES`          | `tpm2.AlgAES`             | `tpm2.TPMAlgAES`            |
| `TPM_ALG_HMAC`         | `tpm2.AlgHMAC`            | `tpm2.TPMAlgHMAC`           |
| `TPM_ALG_NULL`         | `tpm2.AlgNull`            | `tpm2.TPMAlgNull`           |
| `TPM_RH_OWNER`         | `tpm2.HandleOwner`        | `tpm2.TPMRHOwner`           |
| `TPMS_RSA_PARMS`       | `tpm2.RSAParams`          | `tpm2.TPMSRSAParms`         |
| `TPMT_SYM_DEF_OBJECT`  | `tpm2.SymScheme`          | `tpm2.TPMTSymDefObject`     |
| `TPMS_KEYEDHASH_PARMS` | `tpm2.KeyedHashParams`    | `tpm2.TPMSKeyedHashParms`   |
| Handle transiente      | `tpmutil.Handle`          | `tpm2.TPMHandle`            |
| Nome oggetto           | (non esposto)             | `tpm2.TPM2BName`            |

### Attributi oggetto — bitmask vs struct booleana

In v0.3.x gli attributi sono costanti OR-ate in un `uint32`. È facile dimenticare un flag o OR-are costanti incompatibili senza che il compilatore se ne accorga.

```go
// v0.3.x — bitmask, nessun controllo dal compilatore
Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
            tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
            tpm2.FlagRestricted | tpm2.FlagDecrypt
```

In v0.9.x ogni attributo è un campo booleano con nome esplicito, coerente con la specifica TCG Part 2.

```go
// v0.9.x — struct, il compilatore controlla i nomi dei campi
ObjectAttributes: tpm2.TPMAObject{
    FixedTPM:            true,  // bit=1  → chiave non duplicabile
    FixedParent:         true,  // bit=4  → parent non modificabile
    SensitiveDataOrigin: true,  // bit=5  → dati sensibili generati dal TPM
    UserWithAuth:        true,  // bit=6  → autorizzazione con password utente
    Restricted:          true,  // bit=16 → uso limitato a strutture note
    Decrypt:             true,  // bit=17 → può decifrare
    SignEncrypt:         true,  // bit=18 → può firmare o cifrare (sym)
}
```

> **Attenzione:** in v0.9.x il flag `Sign` della specifica TCG si chiama `SignEncrypt` nel tipo Go, perché per le chiavi simmetriche indica cifratura, per le asimmetriche indica firma.

---

## 7. TPM2B — il wrapper per strutture serializzate

In v0.9.x, le strutture complesse della specifica TCG sono avvolte in un container `TPM2B[T]`. Questo tipo generico gestisce internamente la serializzazione binaria nel formato TPM (lunghezza a 16 bit + payload).

```go
// Definizione interna:
type TPM2B[T Marshallable, P interface{ *T; Unmarshallable }] struct {
    contents *T
    buffer   []byte
}

// Per creare un TPM2B si usa New2B:
pub := tpm2.New2B(tpm2.TPMTPublic{ ... }) // restituisce TPM2BPublic

// Per leggere il contenuto da un response:
contents, err := resp.OutPublic.Contents() // restituisce *TPMTPublic
```

In v0.3.x questa serializzazione era implicita e nascosta — passavi direttamente la struct `tpm2.Public{}` senza preoccuparti del formato binario.

---

## 8. Union types — costruttori tipizzati

La specifica TCG usa i tipi union (`TPMU_*`) per rappresentare valori che possono essere di tipo diverso a seconda di un selettore. In v0.3.x questi erano gestiti con puntatori nullable. In v0.9.x si usano costruttori generici che associano il selettore al valore in modo type-safe.

```go
// Seleziona i parametri RSA come tipo di parametri pubblici
Parameters: tpm2.NewTPMUPublicParms(
    tpm2.TPMAlgRSA,         // selettore: dice "i parametri sono RSA"
    &tpm2.TPMSRSAParms{...} // valore: la struct con i dettagli RSA
)

// Seleziona 128 bit come dimensione della chiave AES
KeyBits: tpm2.NewTPMUSymKeyBits(
    tpm2.TPMAlgAES,         // selettore
    tpm2.TPMKeyBits(128),   // valore
)

// Seleziona CFB come modalità AES
Mode: tpm2.NewTPMUSymMode(
    tpm2.TPMAlgAES,         // selettore
    tpm2.TPMAlgCFB,         // valore
)

// Seleziona HMAC come schema per la keyed hash
Details: tpm2.NewTPMUSchemeKeyedHash(
    tpm2.TPMAlgHMAC,        // selettore
    &tpm2.TPMSSchemeHMAC{   // valore
        HashAlg: tpm2.TPMAlgSHA256,
    },
)
```

---

## 9. NamedHandle — perché serve il Name

In v0.9.x, quando passi un handle come parent di un `Create`, devi fornire anche il suo **Name** (`TPM2BName`). Il Name è il digest SHA-256 della `TPMTPublic` dell'oggetto — è l'identità criptografica della chiave.

Il TPM usa il Name per legare criptograficamente ogni chiave figlia al suo parent: se qualcuno tampera con la chiave primaria, il Name cambia e la chiave figlia non può più essere caricata sotto quel parent.

```go
// Sbagliato — passa solo l'handle numerico
ParentHandle: resp.ObjectHandle    // compila ma il TPM potrebbe rifiutare

// Corretto — passa handle + identità criptografica
ParentHandle: tpm2.NamedHandle{
    Handle: resp.ObjectHandle, // TPMHandle — valore numerico (es. 0x80000000)
    Name:   resp.Name,         // TPM2BName  — digest SHA-256 della chiave
}
```

In v0.3.x questo controllo non esisteva — si passava solo l'handle numerico e il TPM eseguiva la verifica internamente senza che il codice Go ne fosse consapevole.

---

## 10. Response — valori multipli vs struct tipizzata

### Legacy v0.3.x

Ogni funzione restituisce valori multipli con tipi generici (`[]byte`, `crypto.PublicKey`, `tpmutil.Handle`). Per accedere ai dettagli devi fare type assertion o deserializzare manualmente i blob.

```go
// CreatePrimary
handle, pubKey, err := tpm2.CreatePrimary(tpm, ...)
rsaKey := pubKey.(*rsa.PublicKey) // type assertion necessaria

// Create
privateBlob, publicBlob, err := tpm2.Create(tpm, ...)
// privateBlob e publicBlob sono []byte — per usarli devi re-serializzarli
```

### Moderna v0.9.x

Ogni comando ha la sua struct response dedicata, con campi tipizzati che corrispondono alla specifica TCG Part 3.

```go
// CreatePrimaryResponse
type CreatePrimaryResponse struct {
    ObjectHandle TPMHandle   // handle transiente in memoria TPM
    OutPublic    TPM2BPublic // chiave pubblica RSA
    CreationData tpm2bCreationData
    CreationHash TPM2BDigest
    CreationTicket TPMTTKCreation
    Name         TPM2BName  // identità criptografica — usala in NamedHandle
}

// CreateResponse
type CreateResponse struct {
    OutPrivate     TPM2BPrivate // blob cifrato da salvare su disco
    OutPublic      TPM2BPublic  // chiave pubblica
    CreationData   tpm2bCreationData
    CreationHash   TPM2BDigest
    CreationTicket TPMTTKCreation
}
```

---

## 11. Esempio completo a confronto

### Legacy v0.3.x — CreatePrimary + Create + FlushContext

```go
package tpm

import (
    "github.com/google/go-tpm/tpm2"
)

func CreateHMACKeyLegacy() (private, public []byte, err error) {
    tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
    if err != nil {
        return nil, nil, err
    }
    defer tpm.Close()

    primaryTemplate := tpm2.Public{
        Type:    tpm2.AlgRSA,
        NameAlg: tpm2.AlgSHA256,
        Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
                    tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
                    tpm2.FlagRestricted | tpm2.FlagDecrypt,
        RSAParameters: &tpm2.RSAParams{
            Symmetric: &tpm2.SymScheme{Alg: tpm2.AlgAES, KeyBits: 128},
            KeyBits:   2048,
        },
    }

    handle, _, err := tpm2.CreatePrimary(tpm, tpm2.HandleOwner,
        tpm2.PCRSelection{}, "", "", primaryTemplate)
    if err != nil {
        return nil, nil, err
    }
    defer tpm2.FlushContext(tpm, handle)

    hmacTemplate := tpm2.Public{
        Type:    tpm2.AlgKeyedHash,
        NameAlg: tpm2.AlgSHA256,
        Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent |
                    tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth |
                    tpm2.FlagSign,
        KeyedHashParameters: &tpm2.KeyedHashParams{
            Alg:  tpm2.AlgHMAC,
            Hash: tpm2.AlgSHA256,
        },
    }

    return tpm2.Create(tpm, handle, tpm2.PCRSelection{}, "", "", hmacTemplate)
}
```

### Moderna v0.9.x — CreatePrimary + Create + FlushContext

```go
package tpm

import (
    "github.com/google/go-tpm/tpm2"
    "github.com/google/go-tpm/tpm2/transport"
)

func CreateHMACKey() (private tpm2.TPM2BPrivate, public tpm2.TPM2BPublic, err error) {
    tpm, err := transport.OpenTPM("/dev/tpmrm0")
    if err != nil {
        return private, public, err
    }
    defer tpm.Close()

    primaryResp, err := tpm2.CreatePrimary{
        PrimaryHandle: tpm2.TPMRHOwner,
        InPublic: tpm2.New2B(tpm2.TPMTPublic{
            Type:    tpm2.TPMAlgRSA,
            NameAlg: tpm2.TPMAlgSHA256,
            ObjectAttributes: tpm2.TPMAObject{
                FixedTPM: true, FixedParent: true,
                SensitiveDataOrigin: true, UserWithAuth: true,
                Restricted: true, Decrypt: true,
            },
            Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
                Symmetric: tpm2.TPMTSymDefObject{
                    Algorithm: tpm2.TPMAlgAES,
                    KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
                    Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
                },
                Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
                KeyBits: 2048,
            }),
        }),
    }.Execute(tpm)
    if err != nil {
        return private, public, err
    }
    defer tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm) //nolint:errcheck

    createResp, err := tpm2.Create{
        ParentHandle: tpm2.NamedHandle{
            Handle: primaryResp.ObjectHandle,
            Name:   primaryResp.Name,
        },
        InPublic: tpm2.New2B(tpm2.TPMTPublic{
            Type:    tpm2.TPMAlgKeyedHash,
            NameAlg: tpm2.TPMAlgSHA256,
            ObjectAttributes: tpm2.TPMAObject{
                FixedTPM: true, FixedParent: true,
                SensitiveDataOrigin: true, UserWithAuth: true,
                SignEncrypt: true,
            },
            Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
                Scheme: tpm2.TPMTKeyedHashScheme{
                    Scheme: tpm2.TPMAlgHMAC,
                    Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC, &tpm2.TPMSSchemeHMAC{
                        HashAlg: tpm2.TPMAlgSHA256,
                    }),
                },
            }),
        }),
    }.Execute(tpm)
    if err != nil {
        return private, public, err
    }

    return createResp.OutPrivate, createResp.OutPublic, nil
}
```

---

## 12. Tabella riepilogativa

| Aspetto                  | Legacy v0.3.x                              | Moderna v0.9.x                              |
|--------------------------|--------------------------------------------|---------------------------------------------|
| Apertura TPM             | `tpm2.OpenTPM()` → `io.ReadWriteCloser`    | `transport.OpenTPM()` → `transport.TPMCloser` |
| Comandi TPM              | Funzioni con argomenti posizionali         | Struct con `.Execute(tpm)`                  |
| Template chiave          | `tpm2.Public{}`                            | `tpm2.New2B(tpm2.TPMTPublic{})`             |
| Attributi oggetto        | `FlagFixedTPM \| FlagFixedParent \| ...`   | `TPMAObject{FixedTPM: true, ...}`           |
| Nomi costanti algoritmi  | `tpm2.AlgRSA`, `tpm2.AlgSHA256`           | `tpm2.TPMAlgRSA`, `tpm2.TPMAlgSHA256`      |
| Nomi costanti handle     | `tpm2.HandleOwner`                         | `tpm2.TPMRHOwner`                           |
| Parametri chiave RSA     | `&tpm2.RSAParams{}`                        | `&tpm2.TPMSRSAParms{}` con union typizzate  |
| Schema simmetrico        | `&tpm2.SymScheme{Alg, KeyBits}`            | `TPMTSymDefObject{Algorithm, KeyBits, Mode}` |
| Schema HMAC              | `&tpm2.KeyedHashParams{Alg, Hash}`         | `TPMTKeyedHashScheme` + `NewTPMUSchemeKeyedHash` |
| Flag firma               | `FlagSign`                                 | `SignEncrypt: true`                          |
| Parent in Create         | handle numerico                            | `NamedHandle{Handle, Name}`                 |
| FlushContext             | `tpm2.FlushContext(tpm, handle)`           | `tpm2.FlushContext{FlushHandle: h}.Execute(tpm)` |
| Response CreatePrimary   | `(tpmutil.Handle, crypto.PublicKey, error)`| `*CreatePrimaryResponse` con Name incluso   |
| Response Create          | `([]byte, []byte, error)`                  | `*CreateResponse{OutPrivate, OutPublic}`     |
| Conformità specifica TCG | Parziale — tipi semplificati               | Completa — nomi 1:1 con TCG Part 2/3        |
| Policy e Sessions        | Supporto limitato                          | Supporto completo                           |
| Manutenzione             | Deprecata (ultimo commit 2022)             | Attiva                                      |


### Content of CreateResponse struct
- OutPrivate : private blob encrypted
- OutPublic : public blob serialized TPM2B
- CreationData : metadatas
- CreationHash : hash of CreationData for verify thath all the datas are authentic
- CreationTicket : specific ticket that bond CreationHash at the TPM


### How load the private and public blob

---

## 13. Sealed Secret — generazione e recupero con Unseal

Un **sealed secret** è un valore segreto generato internamente dal TPM, cifrato dalla chiave primaria e restituito come blob. Puoi salvarlo su disco e recuperarlo in chiaro solo tramite il TPM che lo ha creato.

### Quando usarlo

Quando vuoi che il TPM generi una chiave AES per te — non la generi tu con `crypto/rand`, la genera il TPM. La usi poi in Go per cifrare dati di qualsiasi dimensione senza limiti.

---

### Template per il sealed secret

```go
// TPMAlgNull come schema = sealed data (non HMAC, non firma)
// SensitiveDataOrigin: true = il TPM genera il secret internamente, noi non lo vediamo mai
secretTemplate := tpm2.TPMTPublic{
    Type:    tpm2.TPMAlgKeyedHash,
    NameAlg: tpm2.TPMAlgSHA256,
    ObjectAttributes: tpm2.TPMAObject{
        FixedTPM:            true,
        FixedParent:         true,
        SensitiveDataOrigin: true, // TPM genera il secret internamente
        UserWithAuth:        true,
        // NO SignEncrypt — non firma
        // NO Decrypt     — non decifra direttamente
    },
    Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
        Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull},
    }),
}

createResp, err := tpm2.Create{
    ParentHandle: parentHandle,
    InPublic:     tpm2.New2B(secretTemplate),
}.Execute(tpm)

// salva su disco — il secret è dentro OutPrivate, cifrato dalla chiave primaria
privateBytes := tpm2.Marshal(createResp.OutPrivate)
publicBytes  := tpm2.Marshal(createResp.OutPublic)
os.WriteFile("secret.priv", privateBytes, 0600)
os.WriteFile("secret.pub",  publicBytes,  0644)
```

---

### Come fare Unseal per recuperare il secret

Unseal richiede 3 passi: ricreare la chiave primaria, caricare il blob, fare unseal.

```go
// 1. ricrea la chiave primaria — stesso template, stesso risultato (il TPM è deterministico)
primaryResp, err := tpm2.CreatePrimary{
    PrimaryHandle: tpm2.TPMRHOwner,
    InPublic:      tpm2.New2B(primaryTemplate),
}.Execute(tpm)
defer tpm2.FlushContext{FlushHandle: primaryResp.ObjectHandle}.Execute(tpm)

// 2. carica il blob sotto la chiave primaria
loadResp, err := tpm2.Load{
    ParentHandle: tpm2.NamedHandle{
        Handle: primaryResp.ObjectHandle,
        Name:   primaryResp.Name,
    },
    InPrivate: createResp.OutPrivate, // blob dal disco
    InPublic:  createResp.OutPublic,  // blob dal disco
}.Execute(tpm)
defer tpm2.FlushContext{FlushHandle: loadResp.ObjectHandle}.Execute(tpm)

// 3. unseal — il TPM decifra OutPrivate e restituisce il secret in chiaro
unsealResp, err := tpm2.Unseal{
    ItemHandle: tpm2.AuthHandle{
        Handle: loadResp.ObjectHandle,
        Name:   loadResp.Name,
        Auth:   tpm2.PasswordAuth(nil), // nessuna password
    },
}.Execute(tpm)

secret := unsealResp.OutData.Buffer // []byte
```

---

### Che tipo di secret restituisce Unseal

`UnsealResponse.OutData` è di tipo `TPM2BSensitiveData` con un campo `Buffer []byte`.

La dimensione del secret dipende dal `NameAlg` del template:

| NameAlg | Dimensione secret |
|---|---|
| `TPMAlgSHA256` | **32 byte** |
| `TPMAlgSHA384` | 48 byte |
| `TPMAlgSHA512` | 64 byte |

Con `TPMAlgSHA256` ottieni **32 byte** — esattamente la dimensione di una chiave AES-256.

---

### Usare il secret come chiave AES-256-GCM in Go

```go
secret := unsealResp.OutData.Buffer // 32 byte generati dal TPM

block, err := aes.NewCipher(secret)
gcm, err   := cipher.NewGCM(block)

// cifra
nonce := make([]byte, gcm.NonceSize())
io.ReadFull(rand.Reader, nonce)
ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

// decifra
nonce, data := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
plaintext, err := gcm.Open(nil, nonce, data, nil)
```

Nessun limite di dimensione — Go cifra file di qualsiasi grandezza, il TPM custodisce la chiave.

---

### Flusso completo

```
CreatePrimary  →  chiave RSA parent (storage key, non esce mai dal TPM)
      │
      └── Create(secretTemplate)  →  OutPrivate + OutPublic  →  salvi su disco
                                           │
                                           └── secret generato dal TPM, dentro OutPrivate cifrato

Per usarlo:
      CreatePrimary (stesso template)
            │
            └── Load(OutPrivate, OutPublic)  →  handle in memoria TPM
                        │
                        └── Unseal  →  32 byte in chiaro
                                           │
                                           └── aes.NewCipher  →  cifra/decifra in Go
```
