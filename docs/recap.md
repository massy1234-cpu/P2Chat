# ML-DSA Security Update

## Obiettivo della regressione

Questa regressione introduce un primo livello di hardening software per la gestione delle chiavi ML-DSA e dei materiali sensibili in RAM.

Il problema iniziale era che alcuni valori critici, tra cui `seed`, `eSeed`, `sSeed`, chiave privata e chiave pubblica, potevano restare in memoria ordinaria ed essere osservabili tramite dump della RAM. L'obiettivo non e rendere il sistema "impossibile da violare", ma ridurre in modo concreto l'esposizione dei dati sensibili e pulire la memoria appena possibile.

## Modifiche principali

### 1. Protezione dei buffer sensibili

Nel file [dilithium.go](/Users/massy/Desktop/P2Chat/cirl-custom/circl/sign/mldsa/mldsa87/internal/dilithium.go) alcune variabili sensibili non vengono piu gestite come semplici allocazioni ordinarie, ma tramite `memguard.LockedBuffer`.

Questo porta due benefici pratici:

- blocco delle pagine in RAM tramite `mlock`, per ridurre l'esposizione allo swapping;
- distruzione esplicita del contenuto tramite `Destroy()` quando il dato non serve piu.

I valori coinvolti includono in particolare:

- `seed`
- `eSeed`
- `sSeed`
- porzioni della chiave privata durante generazione e derivazione

### 2. Distruzione della chiave privata

La struct `PrivateKey` contiene ora un riferimento interno al buffer protetto:

```go
buf *memguard.LockedBuffer
```

Questo permette di associare la vita logica della chiave privata alla vita del buffer protetto e di distruggerlo esplicitamente tramite il metodo:

```go
func (sk *PrivateKey) Destroy()
```

In questo modo la chiave non resta in memoria oltre il necessario.

### 3. Rimozione del seed dalla struct

Per scelta progettuale, il seed originale non viene piu conservato nella struct della chiave privata.

La decisione ha un costo funzionale: non e piu possibile ricostruire o replicare la chiave a partire dal seed mantenuto in memoria.

Il vantaggio e che si riduce la superficie di attacco:

- meno dati sensibili persistenti nella struct;
- minore rischio di leak del seed;
- minore rischio di replica non autorizzata della chiave.

## Cifratura della chiave privata

La chiave privata viene protetta appena possibile dopo la generazione. Il flusso attuale e:

1. `password + salt -> Argon2id`
2. chiave derivata a 32 byte -> `AES-256`
3. cifratura della chiave privata con `AES-GCM`

Nel codice client questo passaggio e distribuito principalmente tra:

- [argon.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/argon/argon.go)
- [aes256.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/aes256.go)
- [encryptPrivateKeyMLDSA.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/mldsa/encryptPrivateKeyMLDSA.go)
- [create_mldsa_keys.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/keys/mldsa/create_mldsa_keys.go)

### Argon2id

Sono presenti tre livelli di costo per Argon2id. Il livello piu alto usa molta RAM ed e pensato per massimizzare la resistenza agli attacchi offline, ma ha un impatto prestazionale reale.

Questa scelta e sensata perche permette di bilanciare sicurezza e usabilita in base al contesto.

### Enclave in memoria

Nel flusso di decodifica e riapertura della chiave privata viene usato anche `memguard.Enclave`, che consente di mantenere il contenuto cifrato in memoria fino al momento dell'uso e di riaprirlo con `Open()` solo quando serve.

Questo e un buon compromesso per conservare temporaneamente materiale sensibile senza lasciarlo sempre disponibile in chiaro nello spazio di memoria del processo.

## Rischi residui

L'hardening introdotto migliora la situazione, ma non elimina ogni finestra di esposizione.

I rischi residui principali sono:

- la chiave derivata con Argon2id esiste comunque per un breve intervallo durante l'uso;
- il codice della libreria `circl` non e stato interamente riprogettato per la sicurezza della memoria;
- l'uso di `unsafe.Pointer` per costruire la `PrivateKey` richiede attenzione, anche se qui e una scelta intenzionale e limitata;
- `mlock` riduce il rischio di swapping, ma non basta da solo a dichiarare il sistema "immune ai dump" in senso assoluto.

In altre parole: il progetto e sensibilmente piu robusto di prima, ma non va descritto come impenetrabile. La formulazione corretta e che il rischio viene ridotto e circoscritto.

## Nota su `unsafe.Sizeof`

Nel punto seguente:

```go
sk1 := memguard.NewBuffer(int(unsafe.Sizeof(PrivateKey{})))
sk := (*PrivateKey)(unsafe.Pointer(&sk1.Bytes()[0]))
```

usare `PrivateKeySize` non sarebbe corretto, perche `PrivateKeySize` rappresenta la dimensione serializzata o packed della chiave, non la dimensione della struct Go completa in memoria.

L'uso di `int(unsafe.Sizeof(PrivateKey{}))` e quindi coerente con l'obiettivo di ospitare una `PrivateKey` intera nel buffer protetto.

## Watchdog

Il watchdog intercetta segnali di terminazione o fault e prova a pulire la memoria sensibile prima dell'uscita del processo.

Riferimento: [watchdog.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/errors/watchdog.go)

L'idea e corretta: davanti a `SIGINT`, `SIGTERM`, `SIGSEGV` o `SIGBUS`, il processo riceve il segnale, invoca `memguard.Purge()` e termina con `os.Exit(1)`.

Va comunque tenuto presente che, nei crash piu violenti, non esiste garanzia assoluta che ogni cleanup applicativo riesca sempre a completarsi.

## Persistenza su file

Nel client, allo stato attuale del repository, le chiavi non sono ancora salvate entrambe come `.dat`:

- la chiave privata viene serializzata in protobuf e salvata come `SK.bin`;
- la chiave pubblica viene salvata come `PK.json`.

Riferimenti:

- [saving_mldsa_keys.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/datacontrol/mldsa/saving_mldsa_keys.go)
- [mldsa.proto](/Users/massy/Desktop/P2Chat/cmd/client/internals/proto/mldsa/mldsa.proto)

Nel payload della chiave privata sono gia presenti metadati utili come:

- algoritmo
- parametri Argon2
- `salt`
- `nonce`
- magic byte di versione
- timestamp

La chiave pubblica, essendo pubblica, non richiede cifratura. Tenerla in chiaro evita costo computazionale inutile.

## Organizzazione del codice

La frammentazione dell'ex file `IK.go` in moduli distinti e una scelta buona e gia giustificata dal repository attuale. Le aree oggi risultano separate in modo piu leggibile:

- Argon2
- AES-256
- key management
- data control

I vantaggi pratici sono reali:

- ricerca dei problemi piu rapida;
- file piu piccoli e leggibili;
- test piu semplici da scrivere e mantenere.

## Test presenti

Nel repository sono gia presenti test utili su:

- cifratura e decifratura AES: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- comportamento con password errata: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- fuzz test su encrypt/decrypt: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- scrittura e lettura delle chiavi su file: [saving_mldsa_keys_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/datacontrol/mldsa/saving_mldsa_keys_test.go)

Questa base e gia buona per evitare di costruire il progetto sopra primitive non verificate.

## Bug corretto durante i test

Durante i test e emerso un bug importante: usare direttamente il risultato di `aesKey.Bytes()` e poi chiamare `memguard.WipeBytes()` sullo slice porta a cancellare anche il contenuto protetto referenziato dal buffer originale.

In pratica, questo pattern e pericoloso:

```go
password := aesKey.Bytes()
defer memguard.WipeBytes(password)
```

perche lo slice restituito da `Bytes()` punta alla stessa area protetta.

La correzione concettualmente giusta e copiare prima i byte in uno slice separato e cancellare solo la copia temporanea:

```go
password := make([]byte, len(aesKey.Bytes()))
copy(password, aesKey.Bytes())
block, err := aes.NewCipher(password)
defer memguard.WipeBytes(password)
```

## Test argon e primi benchmark

mi sono accorto in seguito ai primi test che i parametri per argon erano davvero troppo elevati e impiegavano un livello di memoria superiore addirittura a 10Gb il che portava a tempi troppo elevati ma sopratutto avevo **invertito** i livelli di argon che ho aggiustato

i test che ho implementato sono su :
- casi limite di argon, tramite **table-driven**
- benchmark su alcune stringhe che permettono di capire piu o meno iterazioni e prestazioni dei vari livelli ( 1,2,3 )

### Test Argon
qui ho usato la funzione `run` che mi ha permesso di effettuare diversi test e capire quali passavano e quali no, molto utile e pratico nella realtà, inoltre confrontavo gli errori che ho inserito nella struct con quelli che argon mi dava realmente con determianti parametri input errati

### Benchmark Argon
usando sempre `run` ma anche `b.N` ho capito che GO usa quest'ultimo per capire quanti test continuare a fare finchè non ha una tempistica corretta per la quale poi può effettuare un test, precedentemente non andava in quanto b.N è impostato ad 1 secondo e se il test impiega meno fa una sorta di errore dove inserisce valori errati

per effettuare i test ho usato solo una stringa molto lunga come esempio in quanto variare con diverse stringhe può modificare la reale efficacia del test

ho variato i parametri e inoltre impostato il parametro `threads` usato per argon al numero di CPU che la macchina che usa il codice ha a disposizione


### Base testi vari 
ho chiesto a Codex di generarmi dei casi limite e verificare se gli errori venissero gestiti correttamente, in particolar modo sule seguenti funzioni :
- cifratura files e decifratura, verificata con diversi casi limite
- argon effettuati diversi test con casi limite
- datacontrol creati test con casi limite + eventuale scrittura di chiave con corruzione del file, verificato che il file non possa piu essere messo nel programma
  
## Test consigliati come prossimo passo

I prossimi test che hanno piu valore sono:

- usare un tipo diverso di cheksum, hash non basta in quanto una persona potrebbe modificare il tutto e successivamente ricreare il checksum
  
- controllare che quando vado a leggere le paia di chiavi queste siano un paio corretto ( usando una signature come prova )

### HMAC With Proto Structs - TPM

**problem** -> i cant be sure that a key is not compromised without a cypher but the problem is : **what key can i use to cipher these keys ?**
there are 2 solutions :
- use TPM ( interesting solution and best security level ) -> where the TPM store the password for the key and i use the HMAC func with the data key and the password
- use a password that choose the user but this would be have already 2 or more password ( 1 for Private Key encryption and 1 for hashing keys )


i choose ( for educative reasons ) to use the TPM but now i have a new idea, to generate inside the TPM the aesKey also for cipher the Private Key ml-dsa

with this choise the user can choose to :
- use an own password ( exposed temporary on ram ) for cipher the private key mldsa and the other keys 
- use the TPM for generate the keys and use a more secure system for store cipher keys
- is an user want we can combine password + TPM ( codex for merge functions )


### Implement TPM in cipher aes-256

the problem is that the keys mldsa and other keys that i want to use in my architecture are too big for let the TPM cipher so we need to change architecture

the main idea is :
- i request the TPM a small secret
- use the small secret with a KDF for derivation ( argon )
- use the derivation key for  cipher with AES-256

and i have already the main functions for do this job, now i have to implement :
- TPM managment ( linux, windows, apple )
- TPM creation key

then i will pass the secret to argon and then use aes256 for cipher the secret

**optional** -> add a function for merge the secret of user ( password ) with TPM secret


### Problems with this implemetation

i have multiple choises for implement the TPM in the application but all have some type of compromise

there are the ideas 

1. i can generate a secret inside the TPM and the use memguard for use the secret with AES 
    - benefit : super fast and not too much complex for now
    - problems : possible exposure in memory
2. create a Private and Public key inside the TPM for seal and unseal the secret with the cipher but
    - benefit : super secure
    - problems : problems with integrity ( TPM dont support GCM ) and i will need to chunk the secret because the keys are too big


for now i choose to implement the first so
1. generate the **root** secret inside the TPM
2. generate the HKDF with the secret and another secret inside the TPM
3. export the key and put it directly inside a memguard secure memory space ( critic phase )
4. use the key for aes cipher 

for now i think that is the most efficent and realistic architecture for implement in my application

TPM
├── root_key (non esportabile)
├── Derive(root_key, context) → session_key  [in TPM]
└── HMAC(data, root_key) → tag              [in TPM]

Memory (memguard)
└── session_key (solo durante uso)

Storage
├── encrypted_key = AES(session_key, plaintext_key)
└── tag = TPM_HMAC(encrypted_key, root_key)  ← integrity


### TPM implementation

but what is **TPM** ?

is a chip with RAM, NVRAM ( resist to reboot ), crittogrphic engine and PCR registers for sensibles operations
TPM store the keys like a tree

```
Owner Hierarchy (TPMRHOwner)
└── SRK - Storage Root Key
    ├── Chiave A (sealed)
    ├── Chiave B (sealed)
    └── Chiave C (sealed)
```

and everything is wrapped by the keys that are up the key itself

for create a secret inside the TPM we must use the ```tpm2.Create``` function that do :
- create some random bytes
- create the struct tpm2b_private 
``` 
type TPM2BPrivate struct {
    size   uint16  // lunghezza del buffer
    buffer []byte  // il contenuto cifrato
}
```
- cipher the key with the keys of his parents and with the SRK ( storage root key )
- cipher the TPM2BPrivate with the SRK
- return the 
  - OutPrivate -> the secret sealed with all the keys 
  - OutPublic -> metadata about the secret


then when i need to load the key i use ```tpm2.Load``` for :
- pass the OutPrivate and OutPublic
- decipher the key 
- load the key on the internal RAM
- return an **handle** like a refer ( not pointer ) to the specific internal area that contains the key
**IMPORTANT** the handle is NOT a pointer so i cannot access directly to the key in memory , i can only request to the TPM to access to the key

then when i'm done with the key i use ```tpm2.FlushContext``` to remove the key from the internal RAM of the TPM (the handle becomes invalid after this)

---

### TPM HMAC Key — the correct mechanism to export a secret

so far we have seen how the TPM creates and loads generic keys. now let's look at which key type to use for our specific case.

the key type we care about is a **HMAC key** (type `TPM_ALG_KEYEDHASH`). this is how it works:

```
TPM
└── HMAC key (TPM_ALG_KEYEDHASH)
        │   never exportable, never visible outside the TPM
        │
        TPM2_HMAC(handle, label) ← called by the application
        │
        ▼
    output: 32 bytes   ← the ONLY thing that leaves the TPM
```

the fundamental point is this: the **root key never touches the process RAM**. it does not exit during Load, it does not exit during HMAC. the only thing that exits is the HMAC result, which is already derived and reveals nothing about the original key material.

this is very different from "generate a secret and seal it", where the secret exists as plaintext at some point in its lifecycle. with a HMAC key, the raw cryptographic material never exists outside the chip.

#### `TPM2_HMAC` — what it does concretely

```go
// 1. load the HMAC key into TPM (from its sealed form on disk)
hmacHandle, err := tpm2.Load(tpmDev, srkHandle, outPrivate, outPublic)

// 2. the TPM runs HMAC internally using its own key
//    "mldsa-sk-v1" is the label that identifies the purpose (domain separation)
result, err := tpm2.HMAC(tpmDev, tpm2.TPMAlgSHA256, hmacHandle, []byte("mldsa-sk-v1"))

// result is 32 bytes — this is the only data that exits
// the HMAC key stays inside the TPM
```

the `label` matters: using different labels produces different outputs from the same root key. this is called **domain separation** and allows deriving multiple independent secrets without creating any dependency between them.

```
same HMAC key, different labels:

TPM2_HMAC("mldsa-sk-v1")   → secret_A   (protects ML-DSA SK)
TPM2_HMAC("mlkem-sk-v1")   → secret_B   (protects ML-KEM SK in the future)
TPM2_HMAC("integrity-v1")  → secret_C   (HMAC integrity tag for stored files)
```

all three are derived from the same root key but are fully independent.

---

### Dual Factor: TPM + Password — why it is not excessive

the question is legitimate: is adding the user password on top of the TPM secret really necessary?

**yes, it is the correct choice.** here is why.

the TPM secret alone protects against **software** attacks (RAM dumps, remote theft of the encrypted file), but not against **physical** attacks:

```
scenario without password:

attacker physically steals the laptop
    │
    ▼
removes disk, copies SK.bin
    │
    ▼
reinserts disk into the same laptop (the TPM is still there)
    │
    ▼
boots the system, requests the secret from the TPM
    │
    ▼
gets the keys  ← the TPM cannot distinguish the owner from the attacker
```

with password + TPM:

```
attacker steals the laptop
    │
    ├── has the physical TPM
    ├── has SK.bin
    └── does NOT have the password
            │
            ▼
        cannot derive the AES key
        cannot decrypt SK
```

the three required factors are:
1. **SK.bin file** on disk
2. **physical TPM** of the machine
3. **user password**

losing any one of them makes the keys permanently inaccessible.

---

### Creating a secret inside the TPM — full code walkthrough

This section shows the complete Go code to create a TPM-bound HMAC key and derive a secret from it. Every single line is explained.

The library used is `github.com/google/go-tpm/tpm2`, which is the standard Go library for TPM 2.0.

---

#### Step 1 — open the TPM device

```go
tpmDev, err := tpm2.OpenTPM("/dev/tpmrm0")
if err != nil {
    return nil, fmt.Errorf("cannot open TPM: %w", err)
}
defer tpmDev.Close()
```

- `tpm2.OpenTPM("/dev/tpmrm0")` opens a file descriptor to the TPM resource manager. On Linux the resource manager lives at `/dev/tpmrm0` and handles all context management automatically (flushing handles when the process exits, preventing handle exhaustion).
- `tpmDev` is just a file handle — not a pointer into TPM memory, just a channel to send commands.
- `defer tpmDev.Close()` closes the file descriptor when the function returns. This does NOT destroy any keys inside the TPM.

---

#### Step 2 — create the primary key (SRK equivalent)

But first, what is a **template**?
It is a way for the TPM to manage the secret associated with an instance of the template. The secret can be deterministic or non-deterministic depending on the key type.

The **primary key** associates a deterministic secret with the template, so every time we create the primary key from the same template on the same TPM, the secret is always the same.

The **child key** has a NON-deterministic secret, so every time we create an instance of the child key, the TPM generates a different secret.

```go
primaryTemplate := tpm2.Public{
    Type:       tpm2.AlgRSA,
    NameAlg:    tpm2.AlgSHA256,
    Attributes: tpm2.FlagStorageDefault,
    RSAParameters: &tpm2.RSAParams{
        Symmetric: &tpm2.SymScheme{
            Alg:     tpm2.AlgAES,
            KeyBits: 128, // AES-256 offers better quantum resistance, but AES-128 is already more than sufficient here since this key only protects internal child key blobs, not user data directly
        },
        KeyBits: 2048,
    },
}

primaryHandle, _, err := tpm2.CreatePrimary(
    tpmDev,             // the TPM file descriptor
    tpm2.HandleOwner,   // hierarchy: Owner (TPM_RH_OWNER)
    tpm2.PCRSelection{},// no PCR binding for now
    "",                 // hierarchy auth (empty = no password on hierarchy)
    "",                 // key auth (empty = no password on this key)
    primaryTemplate,    // the template that describes the key
)
if err != nil {
    return nil, fmt.Errorf("CreatePrimary failed: %w", err)
}
defer tpm2.FlushContext(tpmDev, primaryHandle)
```

`primaryTemplate` is the instruction set for the TPM describing how to create the key.

Note that the syntax `Type: tpm2.AlgRSA` is a composite literal — we assign to a struct field a constant value defined in the tpm2 library.

For example, `tpm2.AlgRSA` has the value `0x0001`, which is not just a library constant but a specific ID defined by the TPM 2.0 specification that tells the TPM to use the RSA algorithm to generate the key.

<br>

- `tpm2.Public` is the struct that describes what kind of key you want to create. It is the "blueprint" sent to the TPM.
It is called **public** because it represents the **public portion** of the key object in the TPM 2.0 protocol (corresponding to `TPMT_PUBLIC` in the spec). This is public in the cryptographic sense: it contains attributes, algorithms, and the key's *name* — information that can be shared safely. The private part (`TPM2B_PRIVATE`) is the sensitive area, encrypted inside the blob and never exposed.
- `Type: tpm2.AlgRSA` — this primary key is an RSA key. Its job is NOT to sign or encrypt your data directly. Its job is to **wrap and protect child keys** (like our HMAC key). This is why it needs to be a storage key.
- `NameAlg: tpm2.AlgSHA256` — the algorithm used to compute the key's "name" (a unique identity fingerprint of the key inside the TPM). SHA256 is the standard choice.
- `Attributes: tpm2.FlagStorageDefault` — marks this key as a **storage parent**: it can wrap and unwrap child keys. It cannot sign or decrypt user data directly.
- `RSAParameters.Symmetric` — defines how the sensitive area of child keys is encrypted when stored. AES-128 is the symmetric cipher used by the TPM to seal the child's secret material.
- `RSAParameters.KeyBits: 2048` — the RSA key size. 2048 bits is the TPM 2.0 standard for storage keys.
- `tpm2.CreatePrimary` sends all of this to the TPM. The TPM generates the SRK (Storage Root Key) deterministically from the hierarchy seed + template. This means: **calling CreatePrimary with the same template on the same TPM always produces the same key**. No blob needs to be saved to disk for the primary.
**IMPORTANT:** using the same template does NOT mean you can unwrap a secret on a different TPM. If you created the secret inside TPM A, only TPM A can unwrap it, because the key is derived from seeds that are physically bound to that specific chip and never leave it.
- `tpm2.HandleOwner` (= `TPM_RH_OWNER`) — the Owner hierarchy is the normal user-space hierarchy. There are three hierarchies (Owner, Endorsement, Platform). Owner is the right one for application keys.
- `tpm2.PCRSelection{}` — empty means we are NOT binding the key to any PCR values. If you provided PCR values here, the key could only be used when the platform is in a specific measured boot state.
**PCR** (Platform Configuration Registers) are special registers inside the TPM that record measurements of the machine's boot state.
- `primaryHandle` — the handle returned. It is a 32-bit integer that identifies a slot in the TPM's loaded-objects table in RAM. It is valid until you call `FlushContext` or close the device. **It is not a persistent value** — it only exists in the TPM's internal RAM for the duration of the session.
- `defer tpm2.FlushContext(tpmDev, primaryHandle)` — removes the primary key from the TPM's internal RAM when done. The key is NOT deleted — it can always be recreated deterministically. Flushing just frees the RAM slot.

---

#### Step 3 — define and create the HMAC key

```go
hmacTemplate := tpm2.Public{
    Type:    tpm2.AlgKeyedHash,
    NameAlg: tpm2.AlgSHA256,
    Attributes: tpm2.FlagFixedTPM |
                tpm2.FlagFixedParent |
                tpm2.FlagSensitiveDataOrigin |
                tpm2.FlagUserWithAuth |
                tpm2.FlagSign,
    KeyedHashParameters: &tpm2.KeyedHashParams{
        Alg:  tpm2.AlgHMAC,
        Hash: tpm2.AlgSHA256,
    },
}

private, public, err := tpm2.Create(
    tpmDev,             // TPM file descriptor
    primaryHandle,      // parent key that will seal this key
    tpm2.PCRSelection{},// no PCR binding
    "",                 // key auth password (empty for now)
    "",                 // sensitive data (not used here)
    hmacTemplate,       // blueprint for the HMAC key
)
if err != nil {
    return nil, fmt.Errorf("Create HMAC key failed: %w", err)
}
```

- `tpm2.AlgKeyedHash` — this is the TPM key type for HMAC and XOR operations. Unlike RSA or ECC, a KeyedHash key holds a symmetric secret (the HMAC key material) rather than an asymmetric keypair.
- `tpm2.FlagFixedTPM` — the key **cannot be duplicated** to another TPM. This is the flag that makes it hardware-bound: even if someone exports the sealed blob, it is useless on a different TPM.
- `tpm2.FlagFixedParent` — the key cannot be moved to a different parent inside the same TPM. It is permanently tied to `primaryHandle`.
- `tpm2.FlagSensitiveDataOrigin` — the key material was **generated by the TPM itself**, not imported from outside. This is the flag that guarantees the secret was born inside the chip.
- `tpm2.FlagUserWithAuth` — normal user-level authorization is sufficient to use this key (as opposed to requiring special admin-level auth).
- `tpm2.FlagSign` — this key is allowed to perform signing operations. For HMAC keys, "sign" means "compute HMAC". Without this flag the TPM would refuse HMAC requests.
- `KeyedHashParameters.Alg: tpm2.AlgHMAC` — specifies that this KeyedHash key does HMAC (not XOR).
- `KeyedHashParameters.Hash: tpm2.AlgSHA256` — HMAC-SHA256 specifically. The output will always be 32 bytes.
- `tpm2.Create` sends the template to the TPM. The TPM generates random key material internally and returns two blobs:
  - `private` — the key material **encrypted under the parent key** (primaryHandle). This blob is useless without the parent and without this specific TPM.
  - `public` — metadata about the key (type, algorithm, attributes, name). Not secret, but needed to reload the key later.
- **Important**: at this point the key is NOT loaded into the TPM's active RAM. It has been created and returned as sealed blobs. You must call `Load` before you can use it.

---

#### Step 4 — save the sealed blobs to disk

```go
// these two blobs must be persisted — they are needed every time you want to use the key
err = os.WriteFile("tpm_hmac_private.bin", private, 0600)
if err != nil {
    return nil, fmt.Errorf("cannot save private blob: %w", err)
}

err = os.WriteFile("tpm_hmac_public.bin", public, 0600)
if err != nil {
    return nil, fmt.Errorf("cannot save public blob: %w", err)
}
```

- `private` and `public` are just byte slices returned by `tpm2.Create`. They are safe to store on disk.
- `private` looks like random bytes to anyone who reads it — it is AES-encrypted by the parent key inside the TPM. Without the same TPM it is meaningless.
- `public` is readable metadata. It is not a secret but it is needed to reconstruct the key's name and verify integrity on Load.
- `0600` — file permissions: owner read/write only. This is the minimum correct permission for sensitive blobs.
- These two files together are the **persistent form of your HMAC key**. Every time the application starts it reads these, calls `Load`, gets a handle, and uses it.

---

#### Step 5 — load the key and get a usable handle

```go
// read blobs back from disk
private, err := os.ReadFile("tpm_hmac_private.bin")
if err != nil {
    return nil, fmt.Errorf("cannot read private blob: %w", err)
}
public, err := os.ReadFile("tpm_hmac_public.bin")
if err != nil {
    return nil, fmt.Errorf("cannot read public blob: %w", err)
}

// recreate the primary key (it is deterministic, no disk storage needed)
primaryHandle, _, err := tpm2.CreatePrimary(tpmDev, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", primaryTemplate)
if err != nil {
    return nil, fmt.Errorf("CreatePrimary failed: %w", err)
}
defer tpm2.FlushContext(tpmDev, primaryHandle)

// we pass the public and private blobs to Load, using the primaryHandle as parent, to get back the hmacHandle
hmacHandle, _, err := tpm2.Load(
    tpmDev,        // TPM file descriptor
    primaryHandle, // parent key — must be the same one that created this key
    "",            // parent key auth (empty, matches what we set at Create time)
    public,        // public blob from disk
    private,       // private blob from disk — the TPM decrypts this internally
)
if err != nil {
    return nil, fmt.Errorf("Load HMAC key failed: %w", err)
}
defer tpm2.FlushContext(tpmDev, hmacHandle)
```

- `tpm2.Load` takes the sealed blobs and asks the TPM to decrypt `private` using `primaryHandle`. The decrypted key material goes into the TPM's internal RAM (not your process RAM).
- The TPM verifies that the `public` blob is consistent with the decrypted `private` blob. If someone tampered with either blob on disk, `Load` fails here.
- `hmacHandle` — a new handle pointing to the now-loaded HMAC key inside the TPM. This handle is valid for the lifetime of the session.
- The primary key must be recreated with `CreatePrimary` before calling `Load` because a handle is just a reference to the TPM's internal RAM — it does not persist across sessions. `Load` then uses that handle as the parent to decrypt the private blob. Recreating the primary is instant and deterministic (same template = same key every time).

---

#### Step 6 — derive the secret with HMAC

```go
// label is a public domain-separation string — not a secret
label := []byte("mldsa-sk-v1")

// use the loaded hmacHandle to compute HMAC over the label — the key itself never leaves the TPM
result, err := tpm2.HMAC(
    tpmDev,             // TPM file descriptor
    tpm2.AlgSHA256,     // hash algorithm for HMAC-SHA256
    hmacHandle,         // handle to the loaded HMAC key inside the TPM
    label,              // the input data — your domain separation label
)
if err != nil {
    return nil, fmt.Errorf("TPM HMAC failed: %w", err)
}

// immediately move the result into protected memory
secret, err := memguard.NewBufferFromBytes(result)
if err != nil {
    return nil, fmt.Errorf("memguard failed: %w", err)
}
memguard.WipeBytes(result) // wipe the plain slice immediately after — result is the critical secret
```

- `tpm2.HMAC` **uses** the already-loaded key to compute a digest — it does not create anything. The TPM takes `hmacHandle` (the key in its internal RAM) and `label` (your input bytes) and computes `HMAC-SHA256(key, label)` entirely inside the chip.
- `result` is a plain `[]byte` of 32 bytes that arrives in your process RAM. This is the only moment the derived secret exists in regular memory, and it is the most critical value to protect.
- `label` is NOT a secret — it is a public domain-separation string that anyone can know. There is no need to protect it in memory.
- `memguard.NewBufferFromBytes(result)` copies those 32 bytes into a locked, mprotected memory region. From this point the secret is in protected RAM.
- `memguard.WipeBytes(result)` immediately zeroes the original plain slice. The window of exposure is a few microseconds between the HMAC call return and this wipe.
- The HMAC key itself never appeared in `result` — only the derived output did. Even if `result` were leaked, an attacker cannot reverse HMAC to recover the key.


<br>

### Summary

When we want to create a key inside the TPM we must define two types of template:
- **primary** → the SRK that will wrap the child
- **child** → the key we actually want to use

For example we define the primary template:
```
primaryTemplate := tpm2.Public{
    Type:       tpm2.AlgRSA,

    // the Name identifies the key uniquely inside the TPM
    // Name = ( AlgSHA256 || hash(TPMT_PUBLIC) )

    NameAlg:    tpm2.AlgSHA256,
    Attributes: tpm2.FlagStorageDefault, // can seal and unseal child keys
    
    // RSAParameters defines the properties of the RSA key object
    RSAParameters: &tpm2.RSAParams{

        // Symmetric defines the cipher used to encrypt the sensitive area of child keys
        Symmetric: &tpm2.SymScheme{
            Alg:     tpm2.AlgAES,
            KeyBits: 128,
        },
        KeyBits: 2048,
    },
}
```
The primary template uses 2 layers to protect the child:
- **AES (SymScheme)** encrypts the *sensitive area* of the child key — the actual secret material
- **RSA** wraps the AES key itself, binding the child to the parent through key wrapping

Then to instantiate this template and load the primary key into the TPM's RAM, we call `CreatePrimary`:

```
primaryHandle, _, err := tpm2.CreatePrimary(
    tpmDev,             // the TPM file descriptor
    tpm2.HandleOwner,   // hierarchy: Owner (TPM_RH_OWNER)
    tpm2.PCRSelection{},// no PCR binding for now
    "",                 // hierarchy auth (empty = no password on hierarchy)
    "",                 // key auth (empty = no password on this key)
    primaryTemplate,    // the template that describes the key
)
```

<br>
<br>

#### Generate the child key

Now we define the **child key**:
```
hmacTemplate := tpm2.Public{
    Type:    tpm2.AlgKeyedHash,
    NameAlg: tpm2.AlgSHA256,
    Attributes: tpm2.FlagFixedTPM |
                tpm2.FlagFixedParent |
                tpm2.FlagSensitiveDataOrigin |
                tpm2.FlagUserWithAuth |
                tpm2.FlagSign,
    KeyedHashParameters: &tpm2.KeyedHashParams{
        Alg:  tpm2.AlgHMAC,
        Hash: tpm2.AlgSHA256,
    },
}
```

`AlgKeyedHash` is a key type that holds a symmetric secret and can produce a keyed hash (HMAC) from it.
`KeyedHashParameters` defines the algorithm and hash function to use — in this case HMAC-SHA256.
The `Attributes` field defines security properties of the child key: hardware-binding, parent-binding, TPM-generated origin, and usage permissions.

<br>

#### Create the HMAC key

Now, with both templates defined, we create the **HMAC key** sealed under the primary:

```
private, public, err := tpm2.Create(
    tpmDev,             // TPM file descriptor
    primaryHandle,      // parent key that will seal this key
    tpm2.PCRSelection{},// no PCR binding
    "",                 // key auth password (empty for now)
    "",                 // sensitive data (not used here)
    hmacTemplate,       // blueprint for the HMAC key
)
```

In this function we pass:
- the path to the TPM resource manager
- the primary handle (SRK)
- the key auth password (controls who can use the key)
- the hmacTemplate (the blueprint for the child key)

**With this function the TPM creates the child key sealed under the primary.**

When `tpm2.Create` runs, the TPM internally generates:
- **public struct**: attributes and params
- **sensitive area**: the real secret material, not yet encrypted

Then from the **sensitive area** the TPM encrypts with the symmetric scheme (AES), binds it with the parent key (RSA wrapping), and adds integrity checks — this produces the **private blob**.

<br>

#### Load

`CreatePrimary` is called first to recreate the `primaryHandle` in the TPM's RAM (it is deterministic, so no disk storage is needed — a handle is a volatile RAM reference, not a persistent value). Then `Load` is called with the public and private blobs, using `primaryHandle` as the parent — the TPM decrypts the private blob internally and returns an `hmacHandle`. Finally `tpm2.HMAC` uses that handle to **compute** HMAC(key, label) and return the derived output.

#### Step 7 — flush and close

```go
tpm2.FlushContext(tpmDev, hmacHandle)
tpm2.FlushContext(tpmDev, primaryHandle)
tpmDev.Close()
```

- `FlushContext` removes the key from the TPM's internal RAM. the TPM has a very limited number of slots (typically 3). if you do not flush, subsequent Load calls may fail with `TPM_RC_OBJECT_MEMORY`.
- the key is NOT deleted — the sealed blobs on disk are unchanged. next time you need the secret you run the same Load → HMAC → FlushContext cycle.
- `tpmDev.Close()` closes the file descriptor. the `defer` statements placed earlier handle this automatically in the real code.

---

#### Complete picture — what lives where at each step

```
                      DISK                      TPM internal RAM          process RAM
                      ────                      ────────────────          ───────────
after Create:   tpm_hmac_private.bin      (nothing loaded yet)         (nothing)
                tpm_hmac_public.bin

after Load:     tpm_hmac_private.bin      primaryHandle → primary key  (nothing)
                tpm_hmac_public.bin       hmacHandle    → HMAC key

after HMAC:     tpm_hmac_private.bin      primaryHandle → primary key  result []byte  ← brief
                tpm_hmac_public.bin       hmacHandle    → HMAC key

after memguard: tpm_hmac_private.bin      primaryHandle → primary key  secret (mlock'd, mprotect'd)
                tpm_hmac_public.bin       hmacHandle    → HMAC key     result wiped

after Flush:    tpm_hmac_private.bin      (both handles flushed)       secret (mlock'd, mprotect'd)
                tpm_hmac_public.bin

```

the HMAC key material itself never appears in the "process RAM" column. only its 32-byte derived output does, and only briefly before memguard takes over.

---

## Implementazione TPM effettiva

### Architettura finale: Sealed Blob (non HMAC)

Dopo la fase di studio documentata sopra, l'architettura implementata si discosta dall'approccio HMAC descritto nelle sezioni precedenti. La scelta finale è il **sealed blob**:

- il TPM genera internamente un segreto casuale
- lo sigilla sotto la chiave primaria (blob cifrato, inutile su qualsiasi altro TPM)
- i due blob (`OutPrivate` + `OutPublic`) vengono salvati su disco
- quando il segreto serve, si chiama `Unseal`: il TPM disigilla e restituisce il segreto in RAM per un istante, poi `memguard` lo prende in carico

Rispetto all'approccio HMAC:

| aspetto | HMAC key | Sealed blob (scelto) |
|---|---|---|
| il segreto esce mai dalla RAM del TPM? | no (esce solo il derivato) | sì, brevemente durante Unseal |
| complessità | maggiore (label, domain separation) | minore |
| adatto alla fase attuale | no (over-engineering) | sì |

L'approccio HMAC rimane documentato in [`linux_legacy.go`](/Users/massy/Desktop/P2Chat/cmd/client/internals/tpm/linux_legacy.go) come riferimento commentato.

---

### Nuova API go-tpm (command-based)

Il codice legacy mostrato nelle sezioni precedenti usa la vecchia API procedurale di `go-tpm` (`tpm2.OpenTPM`, `tpm2.Create`, ecc.). L'implementazione reale usa la **nuova API command-based**:

```
libreria: github.com/google/go-tpm/tpm2
transport: github.com/google/go-tpm/tpm2/transport/linuxtpm
```

Il pattern cambia da:

```go
// vecchia API (legacy)
tpm2.CreatePrimary(tpmDev, tpm2.HandleOwner, ...)
```

a:

```go
// nuova API (command struct + Execute)
tpm2.CreatePrimary{
    PrimaryHandle: tpm2.TPMRHOwner,
    InPublic:      tpm2.New2B(primaryTemplate),
}.Execute(tpm)
```

**New2B** is a func that convert a normal declaration of the `primaryTemplate` in a TPM compatible struct

ogni comando è una struct con campi espliciti — più leggibile, più type-safe, allineato con la spec TPM 2.0.

un'altra differenza importante è `tpm2.NamedHandle`: nella nuova API, quando si passa un handle come parent a `Load`, bisogna passare anche il `Name` crittografico, non solo l'handle numerico. questo garantisce che il TPM verifichi l'identità del parent prima di procedere.

```go
parentHandle := tpm2.NamedHandle{
    Handle: primaryResp.ObjectHandle,
    Name:   primaryResp.Name,
}
```

---

### Primary template aggiornato

Il template nella nuova API specifica gli attributi e la modalità AES in modo esplicito:

```go
var primaryTemplate = tpm2.TPMTPublic{
    Type:    tpm2.TPMAlgRSA,
    NameAlg: tpm2.TPMAlgSHA256,
    ObjectAttributes: tpm2.TPMAObject{
        FixedTPM:            true,
        FixedParent:         true,
        SensitiveDataOrigin: true,
        UserWithAuth:        true,
        Restricted:          true,
        Decrypt:             true,
    },
    Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgRSA, &tpm2.TPMSRSAParms{
        Symmetric: tpm2.TPMTSymDefObject{
            Algorithm: tpm2.TPMAlgAES,
            KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
            Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB), // CFB esplicito
        },
        Scheme:  tpm2.TPMTRSAScheme{Scheme: tpm2.TPMAlgNull},
        KeyBits: 2048,
    }),
}
```

il template è definito a livello di package (non di funzione) perché `CreateTPMResponse` e `UnsealSecret` devono usare **esattamente lo stesso template**: `CreatePrimary` è deterministico, stesso template + stesso TPM = stessa chiave. se i due template differissero anche di un bit, `Load` fallirebbe.

---

### Secret template: `TPMAlgNull` = sealed blob

Il template del segreto figlio usa `TPMAlgNull` come scheme:

```go
secretTemplate := tpm2.TPMTPublic{
    Type:    tpm2.TPMAlgKeyedHash,
    NameAlg: tpm2.TPMAlgSHA256,
    ObjectAttributes: tpm2.TPMAObject{
        FixedTPM:            true,
        FixedParent:         true,
        SensitiveDataOrigin: true,
        UserWithAuth:        true,
        // nota: niente FlagSign — non è una HMAC key
    },
    Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
        Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}, // sealed blob, non HMAC
    }),
}
```

`TPMAlgNull` come scheme dice al TPM: questo oggetto non è una chiave operativa (non firma, non fa HMAC), è solo un contenitore di dati sigillati. il TPM genera il segreto casualmente internamente e lo sigilla — l'unica operazione permessa è `Unseal`.

---

### Funzioni implementate

Riferimento: [`linux.go`](/Users/massy/Desktop/P2Chat/cmd/client/internals/tpm/linux.go)

#### `AvailableTPM() bool`
controlla la presenza di `/dev/tpmrm0` (il TPM resource manager). restituisce `true` se il file esiste.

#### `StatusTPM() (bool, error)`
legge `/sys/class/tpm/tpm0/tpm_version_major` e verifica che la versione sia >= 2. restituisce `false` con errore se il TPM non è disponibile o la versione non è supportata.

#### `CreateTPMResponse() (*tpm2.CreateResponse, error)`
crea il sealed blob e restituisce la coppia `OutPrivate + OutPublic`. il segreto non esce dal TPM durante questa chiamata — esce solo come blob cifrato. il chiamante deve poi passare la risposta a `StoreBlobs`.

flusso interno:
1. apre `/dev/tpmrm0`
2. `CreatePrimary` con `primaryTemplate` → `primaryHandle`
3. `Create` con `secretTemplate` → `createResp` (contiene private e public blob)
4. `FlushContext` sul primary handle
5. restituisce `createResp`

#### `UnsealSecret(private TPM2BPrivate, public TPM2BPublic) (*memguard.LockedBuffer, error)`
ricrea la chiave primaria (deterministicamente), carica il blob figlio con `Load`, disigilla con `Unseal`, e immediatamente copia il segreto in un `memguard.LockedBuffer` (mlock). i byte grezzi vengono azzerati con `WipeBytes` prima di restituire.

```go
buf := memguard.NewBuffer(len(unsealResp.OutData.Buffer))
copy(buf.Bytes(), unsealResp.OutData.Buffer)
memguard.WipeBytes(unsealResp.OutData.Buffer) // azzeramento immediato
```

la finestra di esposizione in RAM ordinaria è la stessa pochi microsecondi tra `Unseal` e `WipeBytes`.

#### `StoreBlobs(private TPM2BPrivate, public TPM2BPublic) error`
serializza i blob con `tpm2.Marshal` (che produce il formato binario canonico TPM 2.0) e li salva su file tramite `datacontrol.SaveBytesOnFile`:

```
/data/blobs/privateBlob.bin  ← blob cifrato (inutile senza il TPM che l'ha creato)
/data/blobs/publicBlob.bin   ← metadati pubblici (necessari per Load)
```

---

### Flusso completo aggiornato (Sealed Blob)

```
                      DISK                      TPM internal RAM          process RAM
                      ────                      ────────────────          ───────────
after Create:   privateBlob.bin           (nothing loaded yet)          (nothing)
                publicBlob.bin

after Load:     privateBlob.bin           primaryHandle → primary key   (nothing)
                publicBlob.bin            childHandle   → sealed blob

after Unseal:   privateBlob.bin           primaryHandle → primary key   secret []byte  ← brevissimo
                publicBlob.bin            childHandle   → sealed blob

after memguard: privateBlob.bin           primaryHandle → primary key   secret (mlock'd)
                publicBlob.bin            childHandle   → sealed blob   raw bytes wiped

after Flush:    privateBlob.bin           (tutti gli handle flushed)    secret (mlock'd)
                publicBlob.bin
```

---

### Supporto multi-OS

| OS | stato |
|---|---|
| Linux | implementato (`linux.go`) |
| Windows | non ancora implementato (`windows.go` vuoto) |
| macOS | non ancora implementato (`macos.go` vuoto) |

macOS non ha un TPM standard (ha il Secure Enclave, ma con API completamente diverse). Windows ha un TPM accessibile tramite `tbs.dll` (TPM Base Services). entrambi sono lasciati come estensione futura.

---

### Rischi residui aggiornati (TPM)

- il segreto esiste in RAM ordinaria per un brevissimo intervallo tra `Unseal` e `memguard.WipeBytes` — finestra non eliminabile ma molto ristretta
- se il processo viene killato tra `Unseal` e `WipeBytes`, il segreto potrebbe restare in memoria — il watchdog con `memguard.Purge()` riduce questo rischio ma non lo elimina nei crash violenti
- i blob su disco (`privateBlob.bin`) sono inutili senza il TPM che li ha creati, ma la loro integrità non è verificata con HMAC — un attaccante che li corrompe causa un errore al `Load`, non una compromissione silenziosa
- il TPM da solo non protegge da un attaccante con accesso fisico al laptop acceso e al TPM non bloccato — combinare con password (come descritto nella sezione Dual Factor) rimane la scelta corretta

---

## TPM NV Optimization — persisting the primary key

### The problem: CreatePrimary is slow

Every time `CreateTPMResponse` or `UnsealSecret` ran, the first thing they did was call `CreatePrimary`. That command generates a fresh 2048-bit RSA key inside the TPM hardware — a real cryptographic operation happening on a small dedicated chip. Depending on the hardware, that is anywhere from 100ms to 500ms. Every. Single. Time the app touched the TPM.

For a one-off setup this is fine. But once the TPM becomes part of the normal startup flow (decrypt keys → unseal TPM secret → derive AES key → decrypt private key), that cost hits on every launch. It adds up fast and makes the app feel sluggish for no good reason.

### The fix: persist the primary key in NV memory

The TPM has a small area of non-volatile memory ( NV memory ) — think of it as a tiny internal hard drive that survives reboots and power-offs. You can move a transient key (one that lives only in the TPM's internal RAM) into that NV area using the `EvictControl` command, and assign it a **persistent handle**: a fixed 32-bit address you choose in the owner hierarchy range. We use `0x81000001`.

Once the primary key lives there, instead of running `CreatePrimary` every time, you just call `ReadPublic` on the persistent handle. `ReadPublic` is a trivial lookup — no cryptographic computation, no RSA keygen. The TPM just returns the key's metadata and its `Name` (a SHA256 hash that uniquely identifies the key and is used internally for cryptographic binding). Order of magnitude faster.
For `Unseal` the TPM doesn't need the **private key** stored in the TPM, it recalculate only the private key every time we call `Unseal` using the public key, the seed and the parameters 

### Why the sealed blobs stay valid on both paths

Here is the key insight: `CreatePrimary` in TPM2 is **deterministic**. Same template + same physical TPM chip = same key, always. Even after a reboot. Even if the key was flushed from internal RAM and recreated later from scratch. This is a fundamental TPM2 spec guarantee — the primary key is derived from seeds that are permanently burned into the chip and never leave it.

This means the `OutPrivate` + `OutPublic` blobs saved on disk are always valid, regardless of whether the parent was loaded from NV or freshly regenerated via `CreatePrimary`. The sealed child blob is bound to the key material, not to a specific session or handle. So:

- **NV fast path** (primary already persisted): `ReadPublic` → get `Name` → build `NamedHandle` → use as parent
- **CreatePrimary slow path** (first run, or NV not populated yet): generate the same key from scratch → use as parent

Both produce the exact same parent. `Load` and `Unseal` work correctly on both.

### The new function: `EnsurePrimaryNV`

```go
func EnsurePrimaryNV(tpm transport.TPM) (*tpm2.ReadPublicResponse, bool, error) {
    PublicRead, err := tpm2.ReadPublic{ObjectHandle: persistentHandle}.Execute(tpm)
    if err == nil {
        return PublicRead, true, nil
    }
    return nil, false, nil
}
```

Takes a `transport.TPM` connection from the caller (no internal connection opening — shares the caller's connection, single connection for the whole operation). Calls `ReadPublic` on `persistentHandle` for ensure that the **persistent handle** is not empty. If found, returns the full response — that is the Public Key including the `Name` needed to construct a valid `NamedHandle`. If not found, returns `nil, false, nil` — no error, just "not there".

So `PublicRead` is used effectly only for the parameter `Name` that allows the TPM to verify that `PublicRead` really corrispond to the **primary template**

The interface is `transport.TPM` (not `TPMCloser`) because `EnsurePrimaryNV` has no business closing the connection. The caller owns the lifecycle.

### How CreateTPMResponse and UnsealSecret use it

Both functions now follow the same pattern: open one connection, call `EnsurePrimaryNV` on it, branch on the result.

```go
tpm, err := linuxtpm.Open("/dev/tpmrm0")
// ...
defer tpm.Close()

// check if the NV contains something
pubResp, found, err := EnsurePrimaryNV(tpm)

if found && err == nil {
    
    // fast path: primary is in NV, skip CreatePrimary entirely
    parentHandle = tpm2.NamedHandle{
        Handle: persistentHandle,
        Name:   pubResp.Name,
    }
} else {
    
    // slow path: first run or NV not populated
    primaryResp, err := tpm2.CreatePrimary{...}.Execute(tpm)
    // ...
    parentHandle = tpm2.NamedHandle{
        Handle: primaryResp.ObjectHandle,
        Name:   primaryResp.Name,
    }
}
```

One connection, one `ReadPublic` call, no redundant operations. If `ReadPublic` fails (key not there), we fall back to `CreatePrimary` — same result, slightly slower, but correct.

**Note:** with the `EnsurePrimary` we check only if the TPM contains some primary template but doesnt check if the public key corrispond to the primary template, this check will do nextly in this part

```go
loadResp, err := tpm2.Load{
		ParentHandle: parentHandle,
		
		// load the blobs
		InPrivate: private,
		InPublic:  public,
	}.Execute(tpm)
	if err != nil {
		return nil, apperr.Wrap("Load failed", err)
	}
```

if the public key doesnt match the `Load` fail

### Before vs after

Before: every `CreateTPMResponse` or `UnsealSecret` call opened a connection and immediately ran `CreatePrimary` (RSA 2048-bit keygen on hardware).

After:
- first run ever: `CreatePrimary` once, then `EvictControl` stores the key in NV
- every subsequent run: `ReadPublic` on the persistent handle, no keygen at all

The security properties are unchanged. The NV-persisted primary key is the same key that `CreatePrimary` would have generated — it is just cached inside the chip instead of being regenerated each time. The sealed blobs on disk remain hardware-bound to this specific TPM and useless anywhere else.

### Performance Comparison

before the optimization the file `linux_tpm_test.go` did the test in about **15 second each time.**
With the new optimization, the first time is still 15 seconds BUT the other times that we want to create a new secret or `Unseal` a blob the function took only **0.4 seconds** in average, the function `BenchmarkCreateTPMResponse` do this comparison ( use -v option )
So the optimization improve the speed of the operation ( from the second time ) of **30 times faster** than the first one 

The test was conducted in this hardware
```
goos: linux
goarch: amd64
pkg: P2Chat/cmd/client/internals/tpm/linux
cpu: Intel(R) Core(TM) i5-7400 CPU @ 3.00GHz
BenchmarkCreateTPMResponse
```


### implementation of windows TPM interface
luckly windows and linux have the same interface for the managment of the TPM, except for the `openTPM` func that is defined in 2 files, infact linux use the library `linuxtpm` and windows `windowstpm` but the other **function** are the same

remark: the difference between `transport.TPM` and `transport.TPMCloser` is that the first is the **interface**, so declare how send messages to the TPM but cannot close the connetion the second is the interface + the method `Close()`/

### Implementation TPM ( Secure Enclave ) in MacOS
the ecosystem Apple doesn't have a TPM chip inside but use a different type of chip, the **Secure Enclave** and we can access by the **Security Framework** create by Apple that use **CGo** an implementation of C inside GO, so we can execute C code but inside the Go compiler

**Remark** the Secure Enclave don't create the secret inside the chip but derivate the secret from a seed that we have to pass 


