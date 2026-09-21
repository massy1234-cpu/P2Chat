# ML-DSA Security Update

> Current networking reference: see "Login implementation (2026-09-18)" below. Older architecture proposals and message sketches are retained as history and do not override that section.

## Objective of the regression

This regression introduces a first level of software hardening for the management of ML-DSA keys and sensitive materials in RAM.

The initial problem was that some critical values, including `seed`, `eSeed`, `sSeed`, the private key and the public key, could remain in ordinary memory and be observable via RAM dumps. The objective is not to make the system "impossible to compromise", but to concretely reduce the exposure of sensitive data and clean up the memory as soon as possible.

## Main changes

### 1. Protection of sensitive buffers

In the file [dilithium.go](/Users/massy/Desktop/P2Chat/cirl-custom/circl/sign/mldsa/mldsa87/internal/dilithium.go) some sensitive variables are no longer handled as simple ordinary allocations, but through `memguard.LockedBuffer`.

This brings two practical benefits:

- locking of pages in RAM via `mlock`, to reduce exposure to swapping;
- explicit destruction of the content via `Destroy()` when the data is no longer needed.

The values involved in particular include:

- `seed`
- `eSeed`
- `sSeed`
- portions of the private key during generation and derivation

### 2. Destruction of the private key

The `PrivateKey` struct now contains an internal reference to the protected buffer:

```go
buf *memguard.LockedBuffer
```

This allows associating the logical lifetime of the private key with the lifetime of the protected buffer and destroying it explicitly through the method:

```go
func (sk *PrivateKey) Destroy()
```

In this way the key does not remain in memory longer than necessary.

### 3. Removal of the seed from the struct

By design choice, the original seed is no longer kept in the private key struct.

This decision has a functional cost: it is no longer possible to reconstruct or replicate the key starting from the seed held in memory.

The benefit is that the attack surface is reduced:

- fewer sensitive data persisted in the struct;
- lower risk of seed leakage;
- lower risk of unauthorized replication of the key.

## Private key encryption

The private key is protected as soon as possible after generation. The current flow is:

1. `password + salt -> Argon2id`
2. derived 32-byte key -> `AES-256`
3. encryption of the private key with `AES-GCM`

In the client code this step is mainly distributed between:

- [argon.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/argon/argon.go)
- [aes256.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/aes256.go)
- [encryptPrivateKeyMLDSA.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/mldsa/encryptPrivateKeyMLDSA.go)
- [create_mldsa_keys.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/keys/mldsa/create_mldsa_keys.go)

### Argon2id

There are three cost levels for Argon2id. The highest level uses a lot of RAM and is designed to maximize resistance to offline attacks, but it has a real performance impact.

This choice makes sense because it allows balancing security and usability based on the context.

### In-memory enclave

In the private key decode and reopen flow, `memguard.Enclave` is also used, which allows keeping the encrypted content in memory until the moment of use and reopening it with `Open()` only when needed.

This is a good compromise for temporarily keeping sensitive material without always leaving it available in plaintext in the process's memory space.

## Residual risks

The hardening introduced improves the situation, but it does not eliminate every exposure window.

The main residual risks are:

- the key derived with Argon2id nevertheless exists for a brief interval during use;
- the code of the `circl` library has not been entirely redesigned for memory security;
- the use of `unsafe.Pointer` to build the `PrivateKey` requires attention, even if here it is an intentional and limited choice;
- `mlock` reduces the swapping risk, but by itself is not enough to declare the system "immune to dumps" in an absolute sense.

In other words: the project is noticeably more robust than before, but it should not be described as impenetrable. The correct formulation is that the risk is reduced and contained.

## Note on `unsafe.Sizeof`

In the following point:

```go
sk1 := memguard.NewBuffer(int(unsafe.Sizeof(PrivateKey{})))
sk := (*PrivateKey)(unsafe.Pointer(&sk1.Bytes()[0]))
```

using `PrivateKeySize` would not be correct, because `PrivateKeySize` represents the serialized or packed size of the key, not the size of the full Go struct in memory.

The use of `int(unsafe.Sizeof(PrivateKey{}))` is therefore consistent with the goal of hosting an entire `PrivateKey` in the protected buffer.

## Watchdog

The watchdog intercepts termination or fault signals and tries to clean up the sensitive memory before the process exits.

Reference: [watchdog.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/errors/watchdog.go)

The idea is correct: on `SIGINT`, `SIGTERM`, `SIGSEGV` or `SIGBUS`, the process receives the signal, invokes `memguard.Purge()` and terminates with `os.Exit(1)`.

Still, it must be kept in mind that, in the most violent crashes, there is no absolute guarantee that every application cleanup can always complete.

## File persistence

In the client, at the current state of the repository, the keys are not yet both saved as `.dat`:

- the private key is serialized into protobuf and saved as `SK.bin`;
- the public key is saved as `PK.json`.

References:

- [saving_mldsa_keys.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/datacontrol/mldsa/saving_mldsa_keys.go)
- [mldsa.proto](/Users/massy/Desktop/P2Chat/cmd/client/internals/proto/mldsa/mldsa.proto)

The private key payload already contains useful metadata such as:

- algorithm
- Argon2 parameters
- `salt`
- `nonce`
- magic version byte
- timestamp

The public key, being public, does not require encryption. Keeping it in plaintext avoids useless computational cost.

## Code organization

Fragmentation of the former `IK.go` file into distinct modules is a good choice and is already justified by the current repository. The areas are now separated in a more readable way:

- Argon2
- AES-256
- key management
- data control

The practical benefits are real:

- faster problem search;
- smaller and more readable files;
- simpler tests to write and maintain.

## Tests present

The repository already contains useful tests on:

- AES encryption and decryption: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- behavior with wrong password: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- fuzz test on encrypt/decrypt: [encryption_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/encryption/encryption_test.go)
- writing and reading of keys to file: [saving_mldsa_keys_test.go](/Users/massy/Desktop/P2Chat/cmd/client/internals/datacontrol/mldsa/saving_mldsa_keys_test.go)

This base is already good to avoid building the project on unverified primitives.

## Bug fixed during testing

During testing an important bug emerged: using directly the result of `aesKey.Bytes()` and then calling `memguard.WipeBytes()` on the slice leads to deleting also the protected content referenced by the original buffer.

In practice, this pattern is dangerous:

```go
password := aesKey.Bytes()
defer memguard.WipeBytes(password)
```

because the slice returned by `Bytes()` points to the same protected area.

The conceptually correct fix is to first copy the bytes into a separate slice and wipe only the temporary copy:

```go
password := make([]byte, len(aesKey.Bytes()))
copy(password, aesKey.Bytes())
block, err := aes.NewCipher(password)
defer memguard.WipeBytes(password)
```

## Argon tests and first benchmarks

I noticed after the first tests that the argon parameters were really too high and used a memory level even above 10GB, which led to times that were too long, but above all I had **inverted** the argon levels, which I then fixed.

The tests I implemented are on:
- boundary cases of argon, via **table-driven**
- benchmarks on some strings that allow understanding roughly iterations and performance of the various levels (1, 2, 3)

### Argon test
here I used the `run` function which allowed me to perform several tests and understand which ones passed and which ones did not, very useful and practical in reality; moreover I compared the errors I inserted in the struct with those that argon actually gave me with certain wrong input parameters.

### Argon benchmark
always using `run` but also `b.N` I understood that GO uses the latter to figure out how many tests to keep doing until it has a correct timing for which it can then perform a test; previously it did not work because `b.N` is set to 1 second and if the test takes less it does a sort of error where it inserts incorrect values.

to run the tests I used only a very long string as an example, since varying with different strings can modify the real effectiveness of the test.

I varied the parameters and also set the `threads` parameter used by argon to the number of CPUs available on the machine that runs the code.


### Base tests — various
I asked Codex to generate some boundary cases for me and to verify whether the errors were handled correctly, in particular on the following functions:
- file encryption and decryption, verified with several boundary cases
- argon, several tests run with boundary cases
- datacontrol, tests created with boundary cases + possible key writing with file corruption, verified that the file can no longer be loaded into the program


## Tests recommended as next step

The next tests with the most value are:

- use a different type of checksum; hash alone is not enough since a person could modify everything and then recreate the checksum

- check that, when I read the key pairs, they are a correct pair (using a signature as proof)

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

## Actual TPM implementation

### Final architecture: Sealed Blob (not HMAC)

After the study phase documented above, the implemented architecture departs from the HMAC approach described in the previous sections. The final choice is the **sealed blob**:

- the TPM internally generates a random secret
- seals it under the primary key (encrypted blob, useless on any other TPM)
- the two blobs (`OutPrivate` + `OutPublic`) are saved to disk
- when the secret is needed, `Unseal` is called: the TPM unseals and returns the secret to RAM for an instant, then `memguard` takes charge of it

Compared to the HMAC approach:

| aspect | HMAC key | Sealed blob (chosen) |
|---|---|---|
| does the secret ever leave the TPM's RAM? | no (only the derived value exits) | yes, briefly during Unseal |
| complexity | greater (label, domain separation) | lower |
| suitable for the current phase | no (over-engineering) | yes |

The HMAC approach remains documented in [`linux_legacy.go`](/Users/massy/Desktop/P2Chat/cmd/client/internals/tpm/linux_legacy.go) as commented reference.

---

### New go-tpm API (command-based)

The legacy code shown in the previous sections uses the old procedural API of `go-tpm` (`tpm2.OpenTPM`, `tpm2.Create`, etc.). The real implementation uses the **new command-based API**:

```
libreria: github.com/google/go-tpm/tpm2
transport: github.com/google/go-tpm/tpm2/transport/linuxtpm
```

The pattern changes from:

```go
// vecchia API (legacy)
tpm2.CreatePrimary(tpmDev, tpm2.HandleOwner, ...)
```

to:

```go
// nuova API (command struct + Execute)
tpm2.CreatePrimary{
    PrimaryHandle: tpm2.TPMRHOwner,
    InPublic:      tpm2.New2B(primaryTemplate),
}.Execute(tpm)
```

**New2B** is a func that convert a normal declaration of the `primaryTemplate` in a TPM compatible struct

every command is a struct with explicit fields — more readable, more type-safe, aligned with the TPM 2.0 specification.

another important difference is `tpm2.NamedHandle`: in the new API, when passing a handle as parent to `Load`, you must also pass the cryptographic `Name`, not only the numeric handle. this ensures that the TPM verifies the identity of the parent before proceeding.

```go
parentHandle := tpm2.NamedHandle{
    Handle: primaryResp.ObjectHandle,
    Name:   primaryResp.Name,
}
```

---

### Updated primary template

The template in the new API specifies the attributes and the AES mode explicitly:

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

the template is defined at package level (not function level) because `CreateTPMResponse` and `UnsealSecret` must use **exactly the same template**: `CreatePrimary` is deterministic, same template + same TPM = same key. if the two templates differed even by one bit, `Load` would fail.

---

### Secret template: `TPMAlgNull` = sealed blob

The child secret template uses `TPMAlgNull` as scheme:

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

`TPMAlgNull` as scheme tells the TPM: this object is not an operational key (it does not sign, it does not do HMAC), it is only a container of sealed data. the TPM generates the secret randomly internally and seals it — the only permitted operation is `Unseal`.

---

### Functions implemented

Reference: [`linux.go`](/Users/massy/Desktop/P2Chat/cmd/client/internals/tpm/linux.go)

#### `AvailableTPM() bool`
checks for the presence of `/dev/tpmrm0` (the TPM resource manager). returns `true` if the file exists.

#### `StatusTPM() (bool, error)`
reads `/sys/class/tpm/tpm0/tpm_version_major` and verifies that the version is >= 2. returns `false` with error if the TPM is not available or the version is not supported.

#### `CreateTPMResponse() (*tpm2.CreateResponse, error)`
creates the sealed blob and returns the `OutPrivate + OutPublic` pair. the secret does not leave the TPM during this call — it only exits as an encrypted blob. the caller must then pass the response to `StoreBlobs`.

internal flow:
1. opens `/dev/tpmrm0`
2. `CreatePrimary` with `primaryTemplate` → `primaryHandle`
3. `Create` with `secretTemplate` → `createResp` (contains private and public blob)
4. `FlushContext` on the primary handle
5. returns `createResp`

#### `UnsealSecret(private TPM2BPrivate, public TPM2BPublic) (*memguard.LockedBuffer, error)`
recreates the primary key (deterministically), loads the child blob with `Load`, unseals with `Unseal`, and immediately copies the secret into a `memguard.LockedBuffer` (mlock). the raw bytes are zeroed with `WipeBytes` before returning.

```go
buf := memguard.NewBuffer(len(unsealResp.OutData.Buffer))
copy(buf.Bytes(), unsealResp.OutData.Buffer)
memguard.WipeBytes(unsealResp.OutData.Buffer) // azzeramento immediato
```

the exposure window in ordinary RAM is the same few microseconds between `Unseal` and `WipeBytes`.

#### `StoreBlobs(private TPM2BPrivate, public TPM2BPublic) error`
serializes the blobs with `tpm2.Marshal` (which produces the canonical TPM 2.0 binary format) and saves them to file via `datacontrol.SaveBytesOnFile`:

```
/data/blobs/privateBlob.bin  ← blob cifrato (inutile senza il TPM che l'ha creato)
/data/blobs/publicBlob.bin   ← metadati pubblici (necessari per Load)
```

---

### Updated complete flow (Sealed Blob)

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

### Multi-OS support

| OS | state |
|---|---|
| Linux | implemented (`linux.go`) |
| Windows | not yet implemented (`windows.go` empty) |
| macOS | not yet implemented (`macos.go` empty) |

macOS has no standard TPM (it has the Secure Enclave, but with completely different APIs). Windows has a TPM accessible via `tbs.dll` (TPM Base Services). both are left as future extensions.

---

### Updated residual risks (TPM)

- the secret exists in ordinary RAM for a very brief interval between `Unseal` and `memguard.WipeBytes` — a window that cannot be eliminated but is very narrow
- if the process is killed between `Unseal` and `WipeBytes`, the secret could remain in memory — the watchdog with `memguard.Purge()` reduces this risk but does not eliminate it in violent crashes
- the blobs on disk (`privateBlob.bin`) are useless without the TPM that created them, but their integrity is not verified with HMAC — an attacker who corrupts them causes an error at `Load`, not a silent compromise
- the TPM alone does not protect against an attacker with physical access to a powered-on laptop and an unlocked TPM — combining with a password (as described in the Dual Factor section) remains the correct choice

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

# Implementation TPM ( Secure Enclave ) in MacOS

link : [Apple documentation about Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)

the Apple ecosystem does not have a standard TPM chip but uses a completely different security processor: the **Secure Enclave** (SE).
We access it through the **Security Framework**, a C library provided by Apple. because the framework is written in C and Go has no native bindings for it, we will use **CGo** that allows Go code to call C functions directly, compiled together inside the same binary.

**Remark** — unlike what you might expect, the SE *does* generate the P-256 private key entirely inside the chip using its hardware TRNG. what you generate yourself (with `crypto/rand`) is the **payload** you want to protect — for example, 32 bytes to use as an AES-256 key — and that payload is then encrypted *by* the SE key via ECIES. the SE private key never leaves the chip; only the ECIES-wrapped payload lives on disk. this is the fundamental architectural difference from the TPM sealed blob, where the secret itself is generated by the TPM and returned only through `Unseal`.

for this type of project i want to understand deeply how things work, so i will describe the main differences between the TPM and the SE (Secure Enclave) and why the SE is (in almost all circumstances involving a physical attacker) more secure than the TPM.

### Hardware differences

the Secure Enclave is **NOT** a separate chip like the TPM.

if we look at the motherboard of a Windows machine and an Apple device, the difference is immediately visible: the TPM is a discrete chip from a third-party vendor (Infineon, STMicroelectronics, Nuvoton) soldered on the PCB and wired to the CPU via a **SPI or LPC bus** — four physical traces you can probe. the SE, instead, is not a separate chip at all — it is a dedicated ARM processor die living inside the **same SoC package** as the CPU and GPU, with all its components physically isolated from the rest of the system at the silicon level.

it has its own independent SRAM, communicates with the application processor through a **hardware mailbox** system, and its memory is completely invisible to the rest of the chip. not even **root** can read inside the SE memory, because the firewall that enforces this isolation is hardwired into the silicon itself — it is not a software policy, not a kernel flag, not a configuration you can override. it is physical logic gates that implement one rule: only the SE processor can address its own SRAM. the main CPU's physical address space does not include the SE SRAM range at all. even a fully compromised kernel cannot map that memory, because the hardware address decoder simply does not route those requests to the SE.

communication between the main CPU and the SE does not happen over any external bus — it happens through an internal hardware mailbox, a small, strictly-controlled message-passing interface carved directly into the SoC interconnect fabric. this eliminates the entire class of **bus-sniffing attacks** that affect TPM systems.

the full communication stack, from your Go code down to the SE hardware, looks like this:

```
Go code (CGo)
    │
    ▼
Security.framework          (Apple C library — /System/Library/Frameworks/Security.framework)
    │
    ▼
secd                        (Security daemon — system process, not root, communicates via XPC)
    │
    ▼
AppleKeyStore.kext          (proprietary Apple kernel extension)
    │
    ▼
SE hardware mailbox         (internal SoC interconnect — no external bus, not sniffable)
    │
    ▼
sepOS                       (SE's own microkernel OS — immutable, verified at boot by Boot ROM)
```

compare this to the TPM communication stack on Linux:

```
Go code (go-tpm)
    │  builds binary TPM2 command packet (TCG spec — fully public and documented)
    ▼
/dev/tpmrm0                 (kernel character device — TPM resource manager)
    │
    ▼
tpm_tis_spi.ko              (kernel TPM driver — writes bytes to SPI via DMA)
    │
    ▼
SPI bus — 4 physical traces on the PCB   (sniffable but nowadays mitigated)
    │
    ▼
TPM chip                    (discrete microcontroller — Infineon, Nuvoton, etc.)

```

the TPM protocol is fully public (TCG TPM 2.0 Part 3 — Commands). the SE protocol between `AppleKeyStore.kext` and the SE hardware is completely proprietary — Apple does not publish it. you can only interact with the SE through the high-level Security.framework API; there is no `/dev/se` you can write raw commands to.


### UID Key
**the most exciting thing about the SE is the UID key** — the hardware root of trust for everything that happens inside the chip.

this key (256 bits) is generated by the **True Random Number Generator (TRNG)** built into the SE hardware. the TRNG is not a software algorithm — it is a hardware circuit that derives randomness from **thermal noise** (Johnson-Nyquist noise): the quantum-mechanically unpredictable fluctuation of electrons in a resistor caused by thermal agitation. the chip samples these voltage fluctuations at a fixed interval, runs the raw bit stream through a whitening/de-biasing conditioner to remove any statistical skew, and uses the result to generate the UID key the very first time power is applied to the chip. this value is then burned permanently into **OTP fuses** (One-Time Programmable) — a process that physically destroys specific fuse links by running a current pulse through them. once burned, the fuse state is irreversible at the silicon level.

nobody checks the uniqueness of this UID key, but the probabilistic argument makes the check unnecessary. with 256 bits and a high-quality hardware TRNG, the probability of any two Apple devices sharing the same UID key — computed via the birthday paradox over ~2 billion devices — is approximately **10⁻⁵⁹**. for reference, the probability of being struck by lightning is roughly **10⁻¹⁵**. the UID collision probability is **44 orders of magnitude smaller** than that. with numbers this extreme, explicit collision checking would be operationally meaningless.

the UID key is also never read out by anyone, during or after manufacturing. Apple's factory firmware burns it and receives only a "programmed successfully" status — never the value. not even Apple knows your device's UID key. this is by design: it allows Apple to legally and technically guarantee that they cannot decrypt user data even with physical possession of the device.


### Mailbox approach vs bus approach

the macOS kernel cannot read inside the SE memory even if fully compromised — the SE SRAM simply does not appear in the CPU's physical address space. the only communication path is the hardware mailbox, and the mailbox protocol only exposes pre-defined operations (generate key, sign, decrypt). there is no "dump SRAM" operation in the protocol.

the TPM, by contrast, uses a SPI bus where all message traffic — including the plaintext response from an `Unseal` command — travels over physical PCB traces. in 2021, Dolos Group demonstrated this attack in practice: they attached a cheap logic analyzer to the SPI bus, captured the TPM's `Unseal` response during Windows boot, and extracted the BitLocker Volume Master Key in plaintext. the TPM was working correctly and was not tampered with. the attack cost roughly $50 in hardware. (nowadays there are partial mitigations, like TPM + PIN, but the bus-level exposure is a structural property of any discrete TPM on a SPI bus.)

---

### Limitations and Software Differences

while the TPM is far more flexible and grants much more freedom in how an application can use it, the SE is very strict about what it allows.

for example, the TPM supports a wide range of key types: AES, HMAC (KeyedHash), EC P-256, RSA-2048, RSA-4096. the SE exposes only **EC P-256** as the key type generated and stored inside the chip. no RSA, no AES keys in hardware, no HMAC keys. the SE's internal AES engine does exist (sepOS uses it to encrypt P-256 keys at rest in Flash), but it is not accessible to applications through any public API.

the architectural differences go further:

- **no key hierarchy**: the TPM manages keys as a tree (Owner hierarchy → primary key → child keys), where every child is cryptographically bound to its parent through key wrapping. the SE has no hierarchy — each P-256 key is independent. there is no Storage Root Key concept, no parent-child binding.
- **no direct memory management**: with the TPM you control the key lifecycle explicitly — `CreatePrimary`, `Load`, `FlushContext`, `EvictControl`. with the SE, memory is managed entirely by **sepOS**, the SE's internal microkernel. you create a key via Security.framework, it persists in the SE's Flash encrypted under a Class Key derived from the UID, gets loaded into SRAM only during active operations, and is cleared from SRAM immediately after the operation completes. you never control when or how this happens.
- **no TPM Quote / no PCR binding**: the TPM has 24 PCR (Platform Configuration Registers) that accumulate SHA-256 measurements of the boot chain — firmware, bootloader, kernel — through a one-way `extend` operation (`PCR_new = SHA256(PCR_old || new_measurement)`). you can seal a secret to specific PCR values so it can only be unsealed if the platform booted in exactly that measured state. this is how BitLocker's TPM-only mode works. the SE has no PCR equivalent, no boot-state measurement chain, no standard remote attestation mechanism. you cannot bind a SE key to the measured software state of the machine.
- **no internally generated sealed secret**: the TPM with `SensitiveDataOrigin` generates a secret entirely inside the chip and wraps it — the plaintext never exists outside the TPM until `Unseal`. the SE cannot do the equivalent for arbitrary-length secrets. you generate the payload yourself (`crypto/rand`) and the SE encrypts it via ECIES; the SE P-256 private key is hardware-generated and hardware-bound, but the payload bytes are produced in software.
- **authentication model**: the TPM uses password/PIN authorization. the SE uses `SecAccessControl` — you can require Touch ID, Face ID, device passcode, or no authentication at all (`kSecAccessControlPrivateKeyUsage`). for non-interactive CLI applications during development, flag `0` is the correct choice — no biometric prompt, the SE performs the operation silently. in production, `kSecAccessControlPrivateKeyUsage` combined with an explicit `LAContext` passed via `kSecUseAuthenticationContext` is the right approach: the system shows Touch ID as a floating system dialog even from a terminal, as long as the process is running in a user session with a display.
<br>

## How the Secure Enclave manage creation and storage of the secret

the Secure Enclave have a more restrictive architecture, the managment of the secret and the choise of chiper algoritms follow a specific flow designed by Apple

i create a very rudimental scheme on how the Secure Enclave store and create the secret inside the chip

![Scheme-Secure-Enclave](images/Quadretti.png)

there are **2 layers** of security
1. How SE manage the keys and how create it ( not visible )
2. How an app should use the SE for create the secret

**Remark** : Apple have some rules about the use of the memory inside the SE so dont allow to any application to use much memory because is very **limited**

### Layer 1

all the secrets are generated from the [UID Key](#uid-key) that i already mentioned before.

this is a very unique secret and if compromised would compromise all the device security but is designed to avoid this problem and infact is quite impossible to read (neither Apple can) so there isn't this problem.

this key is used infact to derivate the **Class Key**. This type of key is like the parent key but use another type of logic, are divided in 4 types and are all the output of a KDF (Key Derivation Function) deterministic between 2 type of dat, the level of security of these keys are divided for the time that they persist in memory

- Class A : KDF(UID + passcode) or KDF(UID)
- Class B : KDF(UID + passcode)
- Class C : KDF(UID)
- Class D : no key

all describe the type of key and the level of security to use when used

the **Class A** (kSecAttrAccessibleWhenUnlockedThisDeviceOnly or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly) have to deleted immediately from the SRAM when the device is locked again

the **Class B** (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) have to delete from SRAM when the device is shut down or rebooted 

the **Class C** (kSecAttrAccessibleAlwaysThisDeviceOnly) is always accessible infact does not use the passcode

the **Class D** not use the class key to secure the secret, so is like have a layer of security less

this parameter is define by the **kSecAttrAccessible** parameter 


**Note:** because of these keys are created by a deterministic function they are NOT stored in the disk or in the SE memory but are derivated every time and the timing depend on the type of class key we use


#### But what is supposed to do this key ???

when we create a **secret** (is not really a secret but **now** we will call secret) there are 2 keys that we need and 
- Class Key
- **Item Key** (AES)

if you look in the schema you will notice that is the **Item Key** (AES key) that really encrypt the secret because 

- **Item key** encrypt the secret
- **Class key** encrypt the item key

only the **Secret** is stored in the Secure Enclave memory, the Item Key is stored in the disk (specifically in a database) wrapped by his Class Key


### Layer 2

**but effectly what we create?**
**how we manage the secrets and what actually is the secret ?**

spoiler : the secret is the private key pair created with **P-256** a chiper algoritm

When we want create the secret inside the Secure Enclave we really dont create a secret but we pass to the SE 32 random bytes and then use a **ECIES** function that combine a key and the 32 bytes (inside the SE chip)

the function create 3 things in output :
- chipertext
- tag (GCM authentication tag)
- ephimeral key

the nonce is NOT a separate field — it is derived internally by the KDF from sharedPoint + pubEph and never stored in the blob

all these 3 things create the **Public Blob** that is stored on disk via `StoreBlobs()`

to be precise: there are two separate pieces. the **SE P-256 key** is persisted in Keychain automatically via `kSecAttrIsPermanent`.
the **encrypted blob** (pubEph + ciphertext + tag) is saved to disk by `StoreBlobs()`.
the Keychain holds the key that can open the blob; disk holds the blob that needs the key to be opened. they are useless without each other.

---

#### creating the P-256 key inside the SE

the very first thing we do is generate a **P-256 key pair inside the SE**. we call `SecKeyCreateRandomKey` with a set of attributes that tell Security.framework exactly what we want:

- `kSecAttrKeyTypeECSECPrimeRandom` — specific the type of alghoritm (P-256 Curve)
- `kSecAttrTokenIDSecureEnclave` — **this is the flag that puts the key inside the chip**. without it, you get a regular software P-256 key in process RAM.
- `kSecAttrIsPermanent: true` — persist the key in Keychain across reboots. this is the SE equivalent of `EvictControl` on the TPM
- `kSecAttrLabel: "com.p2chat.se-master-key"` — a string identifier for the key. this is the SE equivalent of the persistent handle `0x81000001`.

what `SecKeyCreateRandomKey` returns is a **`SecKeyRef`** — an opaque handle, not the key itself.
this is a value that communicate with the API of apple on which private key use

from the `SecKeyRef` you can extract the **public key** (stored in the Keychain database by defaut) with `SecKeyCopyPublicKey`. the public key is not secret — it can live in process RAM freely. the private key never does.

**important**: `SecKeyRef` does NOT link the secret in the SE to the blob. the link between the two is **cryptographic** — the blob can only be decrypted by the specific `privSE` that corresponds to the `pubSE` used to encrypt it

```
first run  (key does not exist yet)
    SecKeyCreateRandomKey  →  SE generates privSE  →  Keychain persists it  →  SecKeyRef (opaque handler)

subsequent boots  (key already in Keychain)
    SecItemCopyMatching(label="com.p2chat.se-master-key")  →  SecKeyRef
    │
    └── no key generation, no cryptography — just a Keychain lookup
        equivalent of ReadPublic(persistentHandle) on the TPM
```

at every boot after the first, you query the Keychain by label to get back a fresh `SecKeyRef` for the session, then use it to call `SecKeyCreateDecryptedData` on the blob from disk.

---

#### why ECIES — the encryption model

the SE only exposes P-256. P-256 is an **asymmetric** algorithm — you encrypt with the public key, you decrypt with the private key. but P-256 alone cannot directly encrypt arbitrary bytes: it is a key agreement primitive, not a bulk cipher.

**ECIES** (Elliptic Curve Integrated Encryption Scheme) solves this by combining two things:
- **P-256 key agreement** — to derive a symmetric key, using the SE's public key as the anchor
- **AES-GCM** — the actual bulk encryption of your 32-byte payload

the result is a **hybrid scheme**: the hardware binding comes from P-256, the encryption comes from AES-GCM. this is why the output has three components instead of a single ciphertext.


---

#### ECIES encryption and decryption — step by step

the ECIES encryption is based on a point defined in the protocol that allows both sides to calculate the same secret using a specific point on the P-256 curve — without ever exchanging it directly.

**cipher the message** (`SecKeyCreateEncryptedData` — main CPU only, SE not involved):

1. calculate **ephimeral_key** = ephimeral_priv (random number) * G (point on the curve)
   *this is the ephimeral key that goes in the blob — ephimeral_priv is discarded immediately after*
2. calculate the **secret** = ephimeral_priv * publicKeyPermanent
3. derivate the aesKey from the **secret**: aesKey = KDF(secret, ephimeral_key)
4. cipher the plaintext with AES-GCM → **ciphertext** + **tag** (GCM authentication tag)

```
blob = ephimeral_key || ciphertext || tag  → StoreBlobs() saves it to disk
```

**decrypt the message** (`SecKeyCreateDecryptedData` — SE is involved):

1. extract **ephimeral_key** from the blob
2. SE calculates the **secret** = private_key_permanent * ephimeral_key
   *private_key_permanent never exits the SE chip — secret is the only value that exits*
3. derivate the same aesKey = KDF(secret, ephimeral_key)
4. AES-GCM-Decrypt(aesKey, ciphertext, tag) → plaintext (32 bytes)
   *if the tag does not verify → error, no output*

```
plaintext (32B) → memguard.NewBufferFromBytes()  [mlock'd, mprotect'd]
raw slice       → WipeBytes()                    [wiped immediately]
```

**But how can be the same secret?**

because we initially calculate ephimeral_key = ephimeral_priv * G
and then secret = ephimeral_priv * publicKeyPermanent.
**but** publicKeyPermanent = private_key_permanent * G, so:

```
cipher side:  ephimeral_priv * (private_key_permanent * G)
SE side:      private_key_permanent * (ephimeral_priv * G)
              = same point  →  SHARED SECRET
```

**key difference from TPM**: on the TPM, `Unseal` returns a secret the TPM itself generated. on the SE, the 32 bytes come from `crypto/rand` — the SE only provides the hardware-bound ECDH step; AES-GCM runs in Security.framework on the main CPU.

---



### Implementation Approach 

the SE does not have a Go library equivalent to `go-tpm`. all operations are managed through the **Security.framework**, a C library provided by Apple. to interface with it from Go, we use **CGo** — the foreign function interface mechanism that allows Go programs to call C code directly, compiled into the same binary. unlike `go-tpm` which constructs binary TPM2 command packets from a fully public specification, with CGo we call Apple's opaque C functions with no access to the underlying SE protocol.

the CGo header declaration that enables Security.framework access:

```go
//go:build darwin

package tpm

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
*/
import "C"
```

everything that touches the SE in Go goes through `import "C"` and calls into these two frameworks. `CoreFoundation` is needed because Security.framework types (`CFDictionaryRef`, `CFDataRef`, `CFErrorRef`) are all Core Foundation objects with manual reference counting — you must call `C.CFRelease()` on every CF object you receive, or you leak memory.

the mapping from the `common_tpm.go` abstraction to the SE equivalent:

| TPM (`common_tpm.go`) | SE (`macos.go`) |
|---|---|
| `AvailableTPM()` | attempt `SecKeyCreateRandomKey` with SE attributes — specific error code means no SE hardware |
| `GetOrCreatePrimary()` | `SecItemCopyMatching` by label → found: return `SecKeyRef` / not found: `SecKeyCreateRandomKey` |
| `CreateTPMResponse()` | `crypto/rand` → 32 bytes, then `SecKeyCreateEncryptedData` (ECIES) with SE public key |
| `UnsealSecret()` | `SecKeyCreateDecryptedData` (ECIES — SE private key performs ECDH internally, never leaves chip) |
| `StoreBlobs()` | save only the ECIES-encrypted blob on disk — the SE key is already persistent in Keychain |
| `PersistPrimaryNV()` | `kSecAttrIsPermanent: kCFBooleanTrue` in `SecItemAdd` — Keychain survives reboots |
| `EnsurePrimaryNV()` | `SecItemCopyMatching` by label — `errSecSuccess` / `errSecItemNotFound` |
| `persistentHandle (0x81000001)` | string label `"com.p2chat.se-master-key"` in Keychain attributes |
| `DeletePrimaryNV()` | `SecItemDelete` with label query |

adapting the flow of the `common.go` file to the SE's logic and constraints.


# Implementation

Note: all the code that begins with `C.` in Go means that the code executed is C, because CGo treats C like a package

```c
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
```

the first line is a directive for the linker, it tells Go to link the Security and CoreFoundation Apple frameworks into the generated binary

almost all the functions that interact with the SE start with **CF** because they are the initials of **Core Foundation**, the Apple library that manages the interaction between the Secure Enclave and applications

to call `C.SecKeyCreateRandomKey(attrs, &cfErr)` we need to build a `CFDictionaryRef` with the key attributes. instead of building it directly in Go, we define a C helper function `buildSEKeyAttributes()` inside the CGo comment block:

```c
static CFDictionaryRef buildSEKeyAttributes() {
    int bits = 256;
    CFNumberRef cfBits = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &bits);

    const void *keys[] = {
        kSecAttrKeyType,
        kSecAttrKeySizeInBits,
        kSecAttrTokenID,
        kSecAttrIsPermanent,
    };

    const void *vals[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        cfBits,
        kSecAttrTokenIDSecureEnclave,
        kCFBooleanFalse,        // ephemeral: no Keychain storage, no entitlement needed
    };

    CFDictionaryRef dict = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        vals,
        4,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );

    CFRelease(cfBits);
    return dict;
}
```

then in Go we just call it:

```go
func AvailableSE() error {
    attrs := C.buildSEKeyAttributes()
    defer C.CFRelease(C.CFTypeRef(attrs))

    var cfErr C.CFErrorRef
    secret := C.SecKeyCreateRandomKey(attrs, &cfErr)

    if unsafe.Pointer(secret) == nil {
        defer C.CFRelease(C.CFTypeRef(cfErr))
        return fmt.Errorf("Secure Enclave not available, code: %d", int(C.CFErrorGetCode(cfErr)))
    }

    C.CFRelease(C.CFTypeRef(secret))
    return nil
}
```

`CFDictionaryCreate` takes these parameters:

```c
CFDictionaryRef CFDictionaryCreate(
    CFAllocatorRef allocator,
    const void **keys,
    const void **values,
    CFIndex numValues,
    const CFDictionaryKeyCallBacks *keyCallBacks,
    const CFDictionaryValueCallBacks *valueCallBacks
)
```

`allocator` is always `kCFAllocatorDefault`, the memory manager for Core Foundation, it works like `malloc()` but for CF objects

`keys` contains the 4 attribute names:
- `kSecAttrKeyType` — the type of key
- `kSecAttrKeySizeInBits` — the size in bits
- `kSecAttrTokenID` — which hardware token to use (the Secure Enclave)
- `kSecAttrIsPermanent` — whether to persist the key in the Keychain

`values` contains the corresponding values:
- `kSecAttrKeyTypeECSECPrimeRandom` — the only key type the SE supports, P-256. Apple doesn't use RSA for efficiency reasons: P-256 is very efficient, while RSA requires a lot of computation for prime number selection
- `cfBits` — 256 bits
- `kSecAttrTokenIDSecureEnclave` — store and use the key inside the SE
- `kCFBooleanFalse` — ephemeral key, not stored in the Keychain because i have to only verify

`numValues` must match the number of keys and values, in this case `4`

`keyCallBacks` and `valueCallBacks` are structs that manage retain/release of objects inside the dictionary

the call `C.CFRelease(C.CFTypeRef(attrs))` is divided into:
- `CFRelease` — equivalent to `free()` for Core Foundation objects
- `C.CFTypeRef` — a cast to the universal CF object type, required because `CFRelease` accepts any CF object



### Implementation of the permanent secret in the SE

i have described the architecture previously, now let's into the code in a high level and then low
for create the secret inside the SE we have to follow this steps

- create the pair of P-256 inside the SE `SecKeyCreateRandomKey`, it return a `privSERef` that is an opacque handle for identify the private key and know his public part. but this time we have to set the `kSecAttrIsPermanent` at **True**
- get the public key from `privSERef` with the function `SecKeyCopyPublicKey` that return `pubSERef` only handle to the public key load in the RAM
- then get the raw bytes of the public key using `SecKeyCopyExternalRepresentation`, now we have the **public key P-256** associated with the P-256 private key in the SE
- now we can encrpyt the secret we want to pass (32 random bytes) using `SecKeyCreateEncryptedData(pubSERef,algorithm,32bytes)` we dont use directly the raw bytes of the public key, we only use the handler. the function return the public blob of the secret for the decryption : `output blob = ephemeral_pub || ciphertext || tag`
- `StoreBlob()` is a function that i will create that create a file that contains the public blob 


instead, for decryption :
- i have to lookup inside the memory of SE for search the key with the label of the application for understand if there is already the private keym i do this with `SecItemCopyMatching(label="...")`, it return the handler to private key inside the SE if present else null
- loading the public blob from the disk 
- use `SecKeyCreateDecryptedData(privSERef, algorithm, blob)` for unseal the secret. **NOTE** this process is managed entirely from the SE because the private key P-256 does not ever exit from the SE


now move on directly on the code

the main function `CreateSecret` calls `createSEKeys`, which in turn calls `createCFDictionary`. here is what each does.

#### `createCFDictionary` — build the attributes for a permanent key

compared to `buildSEKeyAttributes` in `AvailableSE`, this dictionary has 7 entries instead of 4 — it adds `kSecAttrLabel`, `kSecAttrAccessControl`, and `kSecUseAuthenticationContext`:

- `kSecAttrLabel` — a string identifier, the SE equivalent of the TPM persistent handle `0x81000001`. used later by `getSEKeyWithAuth` to retrieve the key from Keychain.
- `kSecAttrAccessControl` — the ACL that governs usage. `kSecAccessControlPrivateKeyUsage` means every cryptographic operation with this key (sign, ECDH) requires user authentication.
- `kSecUseAuthenticationContext` — passes the unevaluated `LAContext` to Security.framework. when `SecKeyCreateRandomKey` sees an unevaluated context, it triggers Touch ID / Face ID before proceeding.

#### `createSEKeys` — generate and persist the key

```c
static SecKeyRef createSEKeys(CFErrorRef *err) {
    CFDictionaryRef dictionary = createCFDictionary(label, err);
    SecKeyRef privKey = SecKeyCreateRandomKey(dictionary, err);
    CFRelease(dictionary);
    return privKey;
}
```

`SecKeyCreateRandomKey` sends the dictionary through Security.framework → secd → AppleKeyStore.kext → SE mailbox. Touch ID fires here. if the user approves, the SE generates the P-256 key internally and persists it in its Flash encrypted under the Class Key. what comes back is a `SecKeyRef` — an opaque handle to the private key, not the key material itself.

#### `getSEKeyWithAuth` — retrieve the key on subsequent runs

on every boot after the first, the key is already in Keychain. `getSEKeyWithAuth` queries it by label using `SecItemCopyMatching`. a new unevaluated `LAContext` is passed via `kSecUseAuthenticationContext` — Touch ID fires again before the handle is returned.

the query dictionary uses `kSecClass` and `kSecAttrKeyClass` to narrow the search to private keys, then filters by `kSecAttrLabel` and `kSecAttrTokenID` to find exactly the right key. `kSecReturnRef` tells the API to return a `SecKeyRef` handle instead of raw bytes.


## Sign and Apple Developer certificate

Apple usually run application inside a **sandbox**.
Is like a box that is virtually isolate from the rest of the system, was designed for execute code without risk some type of escalation or data breach infact everything executed inside the box (teorically) cannot exit from the box

But when we have to access to some hardware component like the SE, we have to disable this sandbox and, depending on what we need we have to pass different level of security :


### Layer 1 - Entitlements file

during the execution of `TestAvailableSE` i came across a problem:

```go
--- FAIL: TestAvailableSE (0.02s)
    macos_test.go:12: Errore nel test del SE  Secure Enclave not available, code: -34018
FAIL
exit status 1
FAIL    P2Chat/cmd/client/internals/tpm/macos   3.485s
```

the code -34018 is generated by the system and specifically from **security daemon (securityd)** that notice to the process that it does not have the permission to access the requested resource.

in this case the error is generated because we have not declared the required entitlements to access the keychain and the Secure Enclave. Specifically, `keychain-access-groups` must be present and validated by a provisioning profile, without it, `securityd` rejects the operation.

To fix this we have to sign the binary with a `.plist` file that declares the required entitlements. This file tells the system the type of permissions we want and then `securityd` decides to allow or deny them to the process.

as you can see from the code, i isolated the 2 `.plist` files because the functions they cover are different.

the file `entitlements.plist` declares that the process does not use the app sandbox:

```xml
<key>com.apple.security.app-sandbox</key>
<false/>
```

then create the binary file, sign the file and then execute.

```bash
go test -c -o macos.test . && \
codesign -s - --entitlements entitlements.plist --force macos.test && \
./macos.test -test.v
```

`-s -` mean that we use ad-hoc sign that doesnt use an Apple Developer account (we can do this because is local development, is requires in App Store apps)

`--entitlements ...` specify the file entitlements that we will use to sign the binary


**The System** allow ad-hoc sign because this is still a NOT critical operation, we only use the SE for create a temporary secret and NOT for store one, but we will see that when we create a secret inside the SE and we want to keep stored we have to put more certificates


### Layer 2 - Create and store a secret inside the SE

then when i create the C function `createSEKeys` , created the binary, sign it the problem was again the same, code -34018

the problem was that for create and persiste the keys i had to request more permissions and also get a certificate 

the first thing that i did was creating an Apple developer account (free) and link to `Xcode`
this allowed me to create a X.509 certificate (Settings -> Apple Accounts -> Personal Team -> +)

the internal structure is:
```
CN = Apple Development: massimogonnella06@gmail.com (H6SMX58D5C)
OU = Y635V7TUJU
O  = Massimo Gonnella
C  = US
```
is present the common name (CN), the Organization Unit (ON) contains the TEAM ID, the Organization (O) that is me and the Country (C) that is always US 

then i created another entitlements file, the `entitlements_storage.plist` that have inside this parameters plus the previous sandbox parameter:

```xml
<key>com.apple.application-identifier</key>
<string>Y635V7TUJU.com.p2chat</string>

<key>com.apple.developer.team-identifier</key>
<string>Y635V7TUJU</string>

<key>keychain-access-groups</key>
<array>
    <string>Y635V7TUJU.*</string>
</array>
```

`com.apple.application-identifier` the parameter that identify the application to the keychain

`com.apple.developer.team-identifier` specify the TEAM ID, must match with the `OU` of certificate

`keychain-access-groups` allow the application to access to the **keychain** of the SE


**BUT** for access to the keychain and authorize permanent operations we have to add another layer of autorizations the **provisioning profile**


### Layer 3 - provisioning profile and `.app` bundle

the `keychain-access-groups` entitlement is a restricted entitlement. macOS does not trust it only because it is written in `entitlements_storage.plist`: it must also be allowed by a provisioning profile generated by Apple/Xcode for the same Team ID, Bundle ID, certificate, and device.

the provisioning profile contains:

1. Bundle ID: `com.p2chat`
2. Team ID: `Y635V7TUJU`
3. Developer certificate allowed to sign the app
4. Entitlements allowed for the app, including `keychain-access-groups`
5. Authorized Mac device UUID

to create/regenerate the profile we use Xcode:

1. Xcode → File → New → Project → macOS App
2. Bundle Identifier: `com.p2chat`, Team: Apple account / Personal Team
3. Signing & Capabilities → `+` Capability → Keychain Sharing → add `com.p2chat`
4. Build with `⌘B`

Xcode puts the generated `.app` in `DerivedData`, for example:

```bash
~/Library/Developer/Xcode/DerivedData/p2chat-*/Build/Products/Debug/p2chat.app
```

inside that app there is:

```bash
p2chat.app/Contents/embedded.provisionprofile
```

with a free Apple Developer account this profile is valid for 7 days. after expiration, build again from Xcode and copy the new `embedded.provisionprofile` into our test bundle.

#### What `macos_test.app` is

`macos_test.app` is not a normal file: it is a macOS application bundle, which is really a directory with a fixed structure:

```text
macos_test.app/
└── Contents/
    ├── Info.plist
    ├── embedded.provisionprofile
    └── MacOS/
        └── macos.test
```

the important files are:

- `Contents/Info.plist` — declares the Bundle ID and the executable name. `CFBundleIdentifier` must be `com.p2chat`, and `CFBundleExecutable` must match the binary name inside `Contents/MacOS`.
- `Contents/MacOS/macos.test` — the Go test binary created by `go test -c`.
- `Contents/embedded.provisionprofile` — the provisioning profile copied from the Xcode-generated app.
- `Contents/_CodeSignature` is generated from `codesign` when we sign the bundle, this bond the bundle with the binary test file

this bundle is necessary because Keychain/Secure Enclave permissions are tied to a signed application identity. the identity is made from:

- the Bundle ID in `Info.plist`
- the entitlements passed to `codesign`
- the Apple Development certificate
- the embedded provisioning profile

if any of these do not match, `securityd` can reject the operation with `-34018`.

the Bundle ID must be consistent in all places:

```text
Info.plist:
CFBundleIdentifier = com.p2chat

entitlements_storage.plist:
com.apple.application-identifier = Y635V7TUJU.com.p2chat
com.apple.developer.team-identifier = Y635V7TUJU
keychain-access-groups = Y635V7TUJU.*

embedded.provisionprofile:
TeamIdentifier = Y635V7TUJU
application-identifier = Y635V7TUJU.com.p2chat
```

`kSecAccessControlPrivateKeyUsage` was tested and causes `-25293 errSecAuthFailed` even at creation time when no `LAContext` is provided. the Security framework tries to show an authentication dialog, but a CGo test binary has no run loop or WindowServer connection capable of hosting it.

the approach tried was to pre-evaluate a `LAContext` using `dispatch_semaphore` to make the async `evaluatePolicy` call synchronous inside CGo — this caused a `SIGTRAP` crash inside LocalAuthentication. the framework asserts when called from a CGo-locked OS thread that has no active run loop.

### Build and sign sequence


```bash
# enter the macOS TPM package
cd cmd/client/internals/tpm/macos

# 1. compile the Go test binary
go test -c -o macos.test .

# 2. copy the test binary into the bundle
cp macos.test macos_test.app/Contents/MacOS/macos.test

# 3. sign the whole bundle, not only the binary
codesign -f -s 945E1AD0FA3F22DB91B66BA52E00293ACC452238 \
  --entitlements entitlements_storage.plist \
  macos_test.app

# 4. run from inside the bundle
./macos_test.app/Contents/MacOS/macos.test -test.v
```

the identity hash can be checked with:

```bash
security find-identity -v -p codesigning
```

the hash:

```text
945E1AD0FA3F22DB91B66BA52E00293ACC452238
```

is the code signing identity for:

```text
Apple Development: massimogonnella06@gmail.com (H6SMX58D5C)
```

using the hash is more reliable than using only:

```bash
"Apple Development: massimogonnella06@gmail.com"
```

because the full certificate common name also contains `(H6SMX58D5C)`.

after every `go test -c`, the binary changes. this means the previous bundle signature is no longer valid, so the sequence must always be:

1. compile
2. copy into `Contents/MacOS`
3. codesign the bundle again
4. run from `Contents/MacOS`

### What to do when the provisioning profile will expire 
the profile inside `macos_test.app/Contents/embedded.provisionprofile` expires after 7 days (free account). after expiry, signing or Keychain access can fail. fix: open Xcode, build the `com.p2chat` project with `⌘B`, then copy the new profile into the bundle using one exact path from `DerivedData`.

```bash
find ~/Library/Developer/Xcode/DerivedData \
  -path '*/Build/Products/Debug/p2chat.app/Contents/embedded.provisionprofile' \
  -print

cp /exact/path/from/the/find/output/embedded.provisionprofile \
  macos_test.app/Contents/embedded.provisionprofile
```


# small change during a code review

i tought that do the copy of a `mlock()` variable, use it and then call `wipebytes` for clean the variable is a good move but is not, i modified all the reference in the code

is not a good move for 2 reasons:
- i copy the data on a safe memory area in a NOT safe area
- i encrease the time exposure of the data in the memory

use directly `.Bytes()` is better that copy the data on another varible and then wipe it because `.Bytes()` return the direct reference to a data in a safe memory zone, so it cannot be dumped from the RAM 




# Proceed with the implementation of the SE and TPM in the cipher of keys
I start to implement another layer of security (hardware security) for a principal reason: the storage of the AES key that ciphers the MLDSA keys. Now I have to think about an architecture that allows the app to store the keys efficiently and in a very secure way.

For now the app has only the MLDSA-87 keys and I have decided that the SE and the TPM will cipher the MLDSA-87 keys and the ML-KEM (in future).
In my architecture I have already implemented the creation of the MLDSA keys, the encryption and the storage of the keys, but this whole architecture is based on a too fragile and vulnerable foundation for a LOT of reasons:
- password strength and length
- reuse of the password
- possible easy brute-force attack
- if the user forgets the password there is NO way to recover it in this type of architecture because the user does not insert any type of identification data (ex. mail)

So I implemented the TPM and the SE for macOS, Linux and Windows users.

But because the TPM and SE have a very different architecture I thought about 2 different approaches to implement:

## TPM Approach

The idea is that the hardware generates a secret inside the chip, combines it with an optional secret of the user and then creates an AES-256 cipher for encrypting and decrypting the informations.
This is the best method for:
- best performance: I do not use the TPM hardware for ciphering the informations
- best security: it would be better if the informations were ciphered inside the TPM but with the implementation of memguard it is a lot safer
- best user experience: with the help of this layer of hardware security I can put (as optional) the ability to reset the authentication password in case the user forgets it


## SE ( 2 Approaches )

For the SE I intended 2 different approaches:

The SE has more powerful resources and can execute a full process of encryption, so I could encrypt data in 2 different ways:

1. Pass directly data to the SE and let it encrypt all the data inside the chip
   **Pros**:
   - maximum level of security, nothing exposed in RAM
   **Cons**:
   - if the private key inside the SE is destroyed or the data in the SE are not available the data are permanently lost
2. Use the same approach of the TPM, derive a secret inside the SE and then use it to create an AES cipher
   **Pros**:
   - the secret is only protected by the SE, so if I lose it but I remember it I can recover the data
   **Cons**:
   - more insecure due to exposure of data inside the RAM
   
I could implement a lot of ideas for the second approach but all of those cannot respect by design the security idea of P2Chat, because this could mean implementing some kind of wrapping or cryptographic backdoor and this is NOT acceptable from a system that has as first amendment the privacy of its users. So I will keep the first approach, considering the fact that all the data could be unrecoverable if the private key in the SE is lost.


## Functions
I implemented all the function i needed for encrypt with the SE and TPM
I modified the file `aes256.go` for separate the function `CreateChiperAes()` so i could create the secret inside the TPM, extract with `UnsealSecret()` and then use `Combine()` for combine more secret in a single **hash**, this will be the key for the aes cipher. 

i created also some generic tests for the SE and TPM


# Next step : implementation of the ML-KEM keys

before quantum computers the KEM (Key Encapsulation Mechanism) was implemented with P-256 or Curve25519, now the Shor alghoritm can easily resolve this type of computional problem in polinomial time (not exponential), in the 2016 the NIST declared that the CRYSTALS-Kyber would be the next KEM standard (FIPS 203)

this type of key is used for create a share secret between 2 users that cannot comunicate yet directly in a safe way

**How it works? (high level)**
```
Alice (key generation):
  1. Chooses a matrix A (public, deterministic)
  2. Chooses secret s and noise e (small)
  3. Computes b = A*s + e
  4. The public key is (A, b)
  5. The private key is s

Bob (encapsulation):
  1. Takes Alice's public key (A, b)
  2. Chooses s' and e' (small, his own)
  3. Computes u = A*s' + e'                      (ciphertext part 1)
  4. Computes v = b*s' + e'' + encode(secret)    (ciphertext part 2)
  5. The shared secret is inside v, "hidden" in the noise
  6. Sends (u, v) as ciphertext

Alice (decapsulation):
  1. Takes (u, v)
  2. Computes v - u*s = (A*s + e)*s' + encode(secret) - (A*s' + e')*s
  3. By algebraic properties, A*s*s' ≈ A*s'*s (they almost commute)
  4. What remains: encode(secret) + (e*s' - e'*s)  ← very small noise
  5. Decodes and recovers the same secret
```

there are 3 type of **ML-KEM** 512,768,1024, in this project we will use the 768 that is also the raccomendation from NIST
this variant of ML-KEM have very large keys
- Public : 1184 bytes
- Private : 2400 bytes 
- Shared secret : 32 byte
- Chipertext : 1088 bytes

the library ("crypto/mlkem") is very clean so we have not to worry about parameters or other specific things, we can reason on high level

## phases
- Alice generate the key pair `alicePrivate, err := mlkem.GenerateKey768(rand.Reader)`
- Alice extract the public key `alicePublic := alicePrivate.EncapsulationKey()`
- Alice send the public to BOB

- Bob receive the public key and generate 2 things (chipertext and the sharedSecret) : `ciphertext, sharedSecret, err := mlkem.Encapsulate768(rand.Reader, alicePublic)`
- Bob sent to Alice the `chipertext`

- Alice get the `chipertext` from Bob and get the same sharedSecret `sharedSecret, err := bobPrivate.Decapsulate(ciphertext)`

**NOTE** : the `sharedSecret` MUST NOT used like aes-key, is highly insecure for many reasons :
- can use that secret for derivate more secret
- add another layer of security
- more entropy
- is the cryptographic standard 
- more warranties of security

this is a scheme of how this type of keys works
![testo alternativo](images/ml-kem.png)


the lifecycle of these ML-KEM keys will be not the same as the ML-DSA key
infact the ML-DSA is a key that MUST be persistent, is like the identity of the user and for this reason must be stored for a long time, the ML-KEM are used once only for share a secret, so i will use a database for manage these keys

### Database and key mangment

the database i will use is BBolt in fact for the data i have to store this is the best solution
the data on the database will be native encrypted and decrypted only will be necessary to do

i will talk about the structure of the database later, for now i will implement the ML-KEM and a way to save it on the database

BBolt storage scheme is very interesting, infact use only buckets and pair key:values to store data, that is perfect for my application and also very simple and clear

use also only a file, that could be interesting to eventually export for a backup or others uses

i will use **messagepack** for the serialization of the files on the database, this is the fastest method for do this and avoid overhead and create a fast data storage


## buchets

in the database the data will be organized for buchet and the bucket that i will use are
- bundle buchet (one for each server P2Chat)
- real-time comunication
- one for each friend (with all the informations and shared_secret)



## ok, this whole thing is not very practical to use alone, we have to implement 2 other protocols 

the ML-KEM have 2 problems :
- no authentication
- if somebody steal the secret, can decrypt all the conversations
- the chat must work also if one of 2 is offline

for fix these problems we will implement other protocols like :
- PQXDH -> allows to an user to send messag to another in case the other user is offline, keeping an high level of security
  - if Bob is offline, Alice can send to it messages that are stored on the server encrypted and authenticated from Alice, the server cannot by design see the content of the messages, is like a post office box but the box is a bunker 
- Double Ratchet -> solve the problem of "what we do if somebody steal the main secret where all the conversation is encrypted?", well, this protocol change the key at every message we send to the other user, isolating all the conversation, past and future, real cool thing


the explanation of these 2 protocols is in this paper : https://signal.org/docs/specifications/pqxdh/ and https://signal.org/docs/specifications/doubleratchet/ 


this part talk about an implementation at an high level about the server's architecture and how the user application must be designed


# Registration on the server

this part will not request any information about the user, will be full anonymously, that expose the server to BOT and DDoS that we can mitigate using some matematical challenge very hard to solve and Captcha

the user consist in get some user ID totally random and get the bundle to publish on the server
this operation use the same logic used for request a bundle so we will use the bind signature to upload the bundle using a signature and another TOR or VPN circuit

# Using TOR or other intermediate server can expose us to data replacement

for use the TOR network or VPN we have to implement also TSL over TOR but we have to modify the part of the certificate, because today stil use protocols NOT quantum-safe so we have to sign the tunnel with a ML-DSA key

so the server have to create a private and public key for TLS protocols with a ML-DSA protocol

# Bundle request

all the users will have to connect to the server with a VPN/TOR network, for obfuscate their real IP address 
in this phase the goal is to get the bundle of the user that we want to communicate using his nickname or identification token on the server 

the client have to remember a few IP addresses that used in past for not use again those IP adresses and avoid some type of traffic analysis, for example NOT use the same IP addresses from a TOR for request 10 bundle but cycle every time

for garantee that the bundle on the server is from the real user and not from an attacker or the server that replaced the keys we have 2 options :
- commitment scheme with a secret that the users shared off the wire (see section "Commitment Scheme Flow & Bundle Verification (2026-09-21)" below)
- check the safety number of the other user off the wire
the first contact is the most vulnerable, but if we check one of these we can have the warranty that the other user is the real one so in future we will keep as trusted the public Identity Key of the other user, NOT the hash because we could expose to a **Second Preimage Attack** 

then for avoid a possibile network analysis of the server for understand some information about which bundle we extract or other information we have to hide the higher possible number of metadata 

for avoid that the server can understand witch bundle we get we can introduce **ORAM**. Now the user that want some bundle associated with the ID of the user, read all the user ID from the databsae or a big part and do some dummy requests for get some random bundle and the one that have to use, for obfuscate the request to the server

for avoid the traffic data based on the lenght's message we have to put a fixed lenght for most of the messages, for example the request to get some bundles and the bundle itself have the same lenght

and for avoid analysis based on the latency we have to uniform the time of the request for do this i created a possible solution
- Alice want to request a bundle
- Alice get the list of usernames and tell the server the bundle thath she want and some dummy requets
- the server released an anonimous certificate with the time of expires using the bind signature
- Alice wait a random number of second and request the bind to the server using a new TOR or VPN connection using the bind signature

Alice have now the bundle

the same process can be did during the upload of the bundle on the server


# Comunication

once that a user have the bundle and want to comunicate with the other user we could have 2 scenarios :
- the other user is offline
- the other user is online

but how we can design a system where the server have the minimum amount of metadata ?

i will explain the details of my solution in the 2 cases

## But first... how comunicate to the server that the user is online or offline ?

we do not. we have only to check our mailbox periodically

is also important to create a mailbox for some requests like
- request to have a user like friend and trust him
- (optional) have messages that we did not read because we were offine
- ecc...

this allows to everyone to comunicate with the user in the online mode and not in the offline mode

## If the user is offline

i can ask to the user which strategy implement :
- keep the message localy and wait the user to become online then send it, like telegram
- implement a mail box inside the server that store the messages

the system of mailbox can be handled using a bind certificate and not exposing the ID of the mittent but insert the request inside the encryption of the message

## if the user is online

we can send the past messages or can request to start a **real-time** comunication with the chipertext already included and the requester that wait a response to a designed IP address

a **real-time** comunication is a comunication that allow us to create a chat between use and the destination and have a realistic user experience like whatsapp or telegram

but this **real-time** comunication can have 2 options :
- client-server type
- peer to peer


### client-server
this architecture is NOT a real client-server, this architecture could only destroy the mailbox system for the amount of data that will create the mailbox system too much inefficent

and also use the server like a reply server is not convinent for metadata use, infact both users will sacrifice the security level of the entire infrastrucutre for the comunication

the only way is create a Peer to Peer anonimous with onion services and not real IP
or also create a sort of anonimous server where the 2 users connect with a VPN and then comunicate each other using encryption

### peer to peer
this is a way better way to comunicate (and the way i created this app) where the 2 users allows each other to let know the other user their IP addresses and start to comunicate in a peer-to-peer mode using alway a shared_secret (enstablished using the server) and the three-ratchet protocol

i can also implement different ways for the peer to peer 
- directly 
- using IP obfuscation (TOR or VPN)


## MailBox idea

i have 2 options :
- have a large public place where get all the data anonymously (server dont know for who their are)
- have a private mailbox for every user (server know messages)

the type of messages are 2 :
- requests to friendship
- offline messages
- request to real-time comunication

the idea is to create new mailboxes shared at every new N users 
this allow us to manage the mailbox system with more efficency and avoid overhead cause to a big unified mailbox

so when Alice and Bob are friend they share a secret, this is derivate with a PQXDH protocol and use a ratchet like protocol to spin the secret at every message for organize theyself for with mailbox to use

so now the users extract and put their message in these random mailboxes derivated 

another problem is the extraction of all the messages, for do this, we have to link a TAG to the message, so when Alice or Bob download the entire mailbox content, they dont have to try to decrypt all the messages but only the messages with their TAG
the TAG must rotate every time for avoid come other type of analysis attack 

**i remember** that this cost is acceptable, infact we use the server only in the initial phase, where we have to get the frienship of the person and request a real-time conversation, the rest is peer to peer conversation that have no latency, so extremely secure

## change the Identity Key

this process need to implement another pair of key, called **IK Pair Revoke** where if we want to change the IK we have to send a message to the server where we ask to change the IK and sign it with the private part

**BUT** for be effective this method we have to save this key NOT on the device but on another device, like a USB-pen drive or another device isolated from our 


# After the server use

after the server use, the 2 users have 2 options:
- comunicate each other their IP addresses for future comunications, using for example a rendevous point or a point where constantly comunicate their own IP
- continue to start the peer to peer comunication using the server initially


### comunicate to our friends that i am online

i can reuse the system of shared secret to send to their mailbox a message where i tell my friends every N minutes that i am online , inlcuding the day and the hours of the day, for avoid false positive messages
BUT in the case that we have the IP of our friend we can communicate directly to him

### Security Problems

for avoid IP leakage i have to encrypt the IP using the shared_secret with the friend that i get from the first contact and use for rotate in a sort of ratchet for be sure that the comunication is secure and cannot be leaked


# MailBox zero and one

these mailboxes are special infact contains the message of friendship in the first contact
i will separate also these specials mailboxes for efficency and i can separate the users response and requests in the mailbox derivating the number of the mailbox from the nickname or user_ID 

the mailbox one is for responde to the requests 
the mailbox zero is for send the request

## how to do for race condition in frienship request or real-time request

for now i dont care much, but is not too much difficult to solve this kind of problem generally, so i will fix this later


# Implementation of the PQXDH 

this (with the three ratchet) are one of the protocols at the base of this architecture, are so much important that before do all the other things i have to implement these protocols

i have read and understand all the documentation on the signal website and now i will implement in GO this protocol and later also the trhee ratchet

i will implement this protocol using the criptographics primitive and assemble them, i will NOT recreate the criptographics protocol, is higly insecure and out of the scope of this project


This is a really simple schema that illustrate how the protocol PQXDH works
![Testo alternativo](images/PQXDH.png)


in my implementation custom of the PQXDH i will create a hybrid architecture of this protocol, putting the diffie hellman functions and post quantum (ml-kem and ml-dsa) together

the hypotetic bundle on the server  :
- Identity Key (MLDSA)
- Identity Key (XEdDSA)
- MLDSA key signed with XEdDSA
- XEdDSA key signed with MLDSA
- SPK (X25519)
- Last-Resort Key (ML-KEM)
- signed SPK
- signed Last-Resort Key
- ID SPK
- ID Last-Resort Key
- set of one-time-use ML-KEM
- set of one-time-use X25519
- signature of the set ML-KEM
- signature of the set X25519


- IK -> identification 
- signed SPK and ML-KEM -> garantee that the server or nobody have replaced the keys
- ephimeral key -> add entropy at each session
- all the DH (DH1,DH2...) -> bond the identity with the session 
- initial message -> confirm that all the operations had a good result, infact the message decryped with the SK must be correct and must coincide

so , i asked chatGPT to help me doing some calculus 
- ML-DSA public key : 2592 bytes
- sign ML-DSA : 4627
- ML-KEM public key : 1184 bytes
- X25519 public key : 32 bytes
- XEdDSA signature : 64 bytes
- XEdDSA public key : 32 bytes
in total the bundle published on the server would be about 1 MB that is big but using compression and other tecniques can be handle 

BUT for optimize perfomance i have to understand that when the other user (that want to comunicate) request the bundle, would be to request the single one-time key and NOT the entire bundle, this is a must for performance optimization

# Bundle architecture

i will divide the bundles in 2 parts
- private -> this will be stored encrypted on the local database
- public -> this will be published on the server in format JSON

the public database will be very simple, all data will be bytes because the server doesnt need to processo this datas or do other things, the server will have the only function to forward the data

the private bundle have a more complicated architecture infact all the data are sensitive, so the data will stored already encrypted on the local database (BBolt) where all the data will be individually encrpted and a function of **unwrap** will encrypt it using the method use for encrypt the data ( password/TPM/SE )

the IK keys will be stored outside the database

**BUT** we have to understand the 2 times where the app will use this method

## initial comunication

the phase where the 2 users doesnt know each other and doesnt have any type of info about each other, neither the most important secret, the **friendship secret** that is the base of this architecture

so the first type of usage is this, the user have to create the initial message for create the **friendship secret** that will allow the other user to start a real comunicatio using the mailbox system

## Refresh of friendship secret

when the 2 users have a friendship secret and have to comunicate, they can start a request sending the request into the N mailbox that the shared secret can derivate using a sort of ratchet (still dont know how to do) and that start a comunication

but for avoid vulnerability the frindship secret will be refreshed at every sessione that the 2 user do, infact the secret session will be derivate usind the bundle so at this time the 2 users will have 
- session secret
- old friendship secret
and now using the session secret and verifing that they have the correct frindship secret they can refresh the frindship secret and comunicate ( using a HMAC(frinship secret | session secret ))

this is for now the most clean, secure and simple way to do it


## PQXDH and now server

i have implemented the protocol PQXDH into the code, the client side and now i have to implement the functions for the server, specifically the connections, the registration and other things but now we will go in order 


# Server Side ( initial part )

## Goroutines, TOR, VPN and client connection

for this phase i have to implement these functionalities 
i will use 'net' and 'tsl' native libraries in Go for maximise understanding

the goals for this phase are :
- connection between client and server
- TSL certificate
- registration into the server 
- publish of the bundle inside the server


### creation of the connection

the server have to do :
- create a ML-DSA key for garantee the identity of the server himself
- create and sign the certificate 
- keep safe the private key ML-DSA 

but for every connection :
- client and server generate a pair ML-KEM + X25519 
- they comunicate their keys using the certificate 
- they derivate a shared secret for comunicate in a secure way ( the server must prove that is he signing with the private key ml-dsa )


the steps are :
- TCP handshake 
  - A send x to B (SYN)
  - B receive x, send to A x+1 and y (SYN/ACK)
  - X send to B y+1
  - **now the 2 user have a enstablished connection TCP**
- clientHello + serverHello -> **encrypted connection enstablished**

the clientHello request the server some data like the keys and the protocol to use + send to the server his session public key (X25519 + ML-KEM ) than the server respond with a serverHello and send to the client his ephimeral key ( X25519 + ML-KEM ), the certificate and the **transcript hash** a particular hash that contains :

```go
Transcript =
    ClientHello ||
    ServerHello ||
    EncryptedExtensions ||
    Certificate ||
    CertificateVerify ||
    Finished
```

where the `EncryptedExtensions` contains some information about the comunication like the protocol used, the `CertificateVerify` is the sign of the server with his private certificate key and finished is the `HMAC(FinishedKey,TransriptHash)` where the finishedkey is a key derivated during the handshake with the X25519 key exchange 

for the TSL documentation i readed **https://tls13.xargs.org/#client-hello**

### Recap of TSL 1.3

i did a recap of the protocol using https://excalidraw.com which i find really useful

![immagine](images/P2Chat.svg)

but i will not use this protocol without edits but i will introduce a small edit for garantee the post quantum security in this protocol because is not already post quantum

i will introduce a EKM secret derived from the master secret where
- the server will calculate it and sign with the private MLDSA key that only he have
- the user will do the same, calulcating the EKM secret and verifing the EKM signed received from the server and match with his EKM, if this match the conversation is fully secured and we can fully trust of the server

now i will implement this in the project

the function `Initialize` in the server folder initialize the MLDSA key and store if NOT present, this will add the EKM layer in the final part of TLS 1.3 protocol custom

### Log console ( small regression )

until NOW the function that i have created had to terminate if some error pop-out but now with the network is different, errors are different and NOT all the type of errors required to terminate the function, so... i have to create a console log more detailed and un future this console will implement all the errors in the application and will give to the owner of the server a general status of the service P2Chat on it, full respecting the privacy of the users

i will use a JSON format log, is more clean, more detailed and i can do research in a easies way match to the current method 


### Registration phase

so... the client will connect to the server and send a registration request, this phase is particulary sensitive cause of some bad user or DDoS network that could be attack easily the server cause of the NO KYC policy of this project

i will implement in future some blocker for block the suspicious requests at a network level but will be hard cause the TOR network, i could use some tecniques but this will be threat in future

the main idea of registration is to avoid all kind of metadatas that the client could give to the server, so the client will connect to the server via TOR or VPN and then request a token foor registration with a bind signature ( for save space )
the client after receive this token will have to opne anoother connection with the server and then use this token for request a ID token that will be his identificator on the server and upload his PQXDH bundle, that will allow the other users to start a comunication with the user 

for this phase i choose the following architectural choises
- server database : badgerDB ( easy data to manage, very fast, internal data managment very interesting )
- blind signature protocol : Blind BLS ( the first choice was Schnorr Ristretto255 but i changed idea cause the ROS attack, a one-more-signature forgery that exploit the reuse of the nonce in parallel signing sessions, the classic blind Schnorr is vulnerable to this and my registration flow is exactly the worst case for this attack because i have many clients in parallel asking tokens, Blind BLS instead is immune to this class of attacks, has no concurrency problems ( every session is independent, there is no nonce commitment to coordinate ), the signatures are short and the performances are optimal, and the security is proven under the One-More-BDH assumption )
- for get the token the client will have to pass a PoW ( is not the solution for DDoS attacks but i could implement this PoW and replace it with for example crypto mining for get a small rewards for the free service )

in past i choosed to use the Ristretto255 protocol with Schnorr 
both protocol are not PQ safe but in this case is not relevant, the token last only few minutes and is NOT critical broke the signature and create new bundle, because in worst case the server becomes sature of bundles and crash but the users privacy is NOT compromised, this is important

the differences between the old and new protocol for blind signature are :
- no nonce needed 
- smaller sign
- this new protocol is not ROS vulnerable 
the ROS attack is a vulnerability in the server side where the server reuse the nonce and the attacker is capable to reproduce a fake signature without the sign of the server
is not critical because in the worse scenario the server could go down cause of too much bundles but this does not influence the users privacy at all

i created a scheme on paper ![paper_scheme](images/IMG_5903.jpg)

converted in markdown for more detailed and clean description

# Blind BLS — Flow schema

## 0. Scalar vs Point — the fundamental distinction

| | **Scalar** | **Point on the curve** |
|---|---|---|
| What it is | An integer, nothing more | A pair of coordinates `(x, y)` |
| Where it lives | In the interval `{0, ..., ℓ-1}` (ℓ = group order) | On the curve: must satisfy `y² = x³ + a·x + b mod p` |
| Examples in our scheme | `x` (private key), `r` (noise), `r⁻¹` | `M`, `M'`, `σ`, `σ'`, `G`, `Y` (public key) |
| Does it have coordinates? | No | Yes, always |

**Multiplying a scalar by a point** (e.g. `r · M`) **is not** a normal multiplication between numbers — it is **repeated addition** of the point to itself, `r` times, using the geometric rule for adding points on an elliptic curve (secant/tangent line + reflection). In practice it is computed quickly with the **double-and-add** algorithm, not by literally adding `r` times.

The result of `scalar · point` is **always another point** — never a number. That is why `M`, `M'` and `σ` are all points in the scheme below: they derive from one another through scalar multiplications, but they always remain points on the curve.

## 1. Hash the message to a number

```
u = SHA-256(msg) mod p
```

`u` is passed to the map-to-curve function (BLS12) → I obtain the point:

```
M
```

## 2. Masking M with the noise R

```
M' = M multiplied by the noise r
```

> It would be a repeated sum (`M + M + ... + M`, r times) — **hard to invert**.

Geometrically: intersection between the curve and the points of `M` and then... repeated on the x axis, repeated `r` times (double-and-add).

## 3. The client sends M' to the server

```
Client ────────── M' ──────────> Server
```

## 4. The server signs blindly

```
Server performs:  σ' = x · M'
```

x = server private key (**random**, it is a random number)

```
Server ────────── sends to client ──────────> σ'
```

## 5. The client removes the noise

```
Client performs:  σ = r⁻¹ · σ'
```

→ **Noise removed**: the signature now remains. The server **does not know** what was signed.

## 6. The client sends (σ, msg) to the server

```
Client ────────── sends (σ, msg) ──────────> Server
```

## 7. The server verifies

```
Server verifies:  msg + σ + Y  (Y = public key)
```

- `msg` → **initial message**
- `σ` → **signature**

Output: **the server does not know it has already signed** this specific (msg, σ) — it cannot link it back to the original signing session (blindness).
'''

the implementation in the code is available in the codebase (server -> blind signature)

### Network package managment 


![image](Images/network_architecture.png)

Okay, so I have redesigned the entire infrastructure of my application.
Now, the client can connect to the server using a multiplexing system. I plan to implement dynamic features in the future, but for now, this system consists of creating multiple logical connections over a single physical connection secured by the TLS protocol.

The library that provides these logical connections is called Yamux. This approach allows me to achieve high performance because each logical connection is responsible for a specific task, while all of them operate independently at the network level without causing issues at the application level.

In fact, every task that requires modifications to the global state of the application is managed by a single component called the Manager. This system allows the application to separate its layers clearly. The network layer is managed by the Session and Connection abstractions, wrapped into clean and well-defined Go structs.

This separation of layers allows me to maximize performance at the network level while keeping the application logic clean and well-coordinated. All operations that modify the global state of the application—such as disk writes or state updates—will be handled via the Manager. The Manager acts as a router/orchestrator: it receives events or tasks from the network sessions and redirects them to the correct function or component responsible for processing them.

Although BadgerDB natively supports safe concurrent operations and thread-safe transactions, centralizing data writes through the Manager (or dedicated DB queues) prevents unnecessary write conflicts and simplifies state tracking.

All advanced optimizations will be implemented in the future, only after the core architecture has been fully implemented and tested. An interesting future optimization could be running worker pools or goroutines inside the Manager for independent CPU-bound tasks (like key generation), while relying on BadgerDB’s native batching features for optimal I/O throughput.

For now, my main focus remains on building a solid, clean, and well-tested initial implementation.


during the implementation i thought about network risks analysis and so even the connection with the server will be on a TOR network ( that implement native the 512 byte padding ) the TOR doesnt not protect in case a user listen and analyze the network from the client and from the server or also the server if is compromised could analyze the network traffic and extract some sensible metadatas



### a small regression about the architecture

i want to specify that i am fully aware about the QUIC protocol and that in this case could offer a lot of interesting features like changing connection handling or internal multiplexing and other that are also more efficent than my approach but this project is mainly created for learning and also i want the full control about the protocol, my choise is derivated from these motivations

### manage the closing 
i use **sync.Once** for avoid goroutiness concurrency and avoid panic signals, in this way is impossible to do a close() in the same time of another goroutiness


### Tor network 
i'm creating the tor layer for garantee the user full anonymously on the server
the process is divided into 3 parts :
- Deamon start ( tor.Start() ) -> start the deamon in background and set DisableNetork=1, so prepare only the system
- Dial() -> connect the client with the 3 nodes on the network and create a connection user -> tor nodes -> server using a TCP connection, the network between nodes is safe, garantee the anonymously but is not safe for data transfer and the server is not trusted yet
- use tls.Client() for wrap the TCP connection into the TLS layer and start to comunicate with the server


### Server side

i tried to create the most symmetrical and coherent network architecture possible between the client side and the server side.
The basic structure, common to both sides, is a single process per session called the **Router** which is the only consumer of the `Incoming` channel. The Router dispatches every message to the **Handler** of the corresponding phase and, based on the result, sends the responses, sets a timeout on the evolution of the phase, or closes the stream.

### "Phase" abstraction (phases)

To make every phase (registration, bundle, chat, ...) autonomous and encapsulated, a shared "phase" convention has been introduced on both the client and server side:

- **Uniform Handler**: `func(byteCode byte, msg []byte, state *any) *phases.Result`
- **`phases.Result`** — the outcome of a single phase step, with fields:
  - `Replies [][]byte` (messages to send, already with the tag inline)
  - `NextDeadline time.Duration` (timeout for the next step, applied by the Router with `timer.Reset`)
  - `Completed bool` (phase concluded successfully)
  - `CloseStream bool`
  - `Err error`
  - helpers `phases.FillResult(...)` and `phases.StripTag(msg, tag)` to remove/verify the first byte.
- **`GetPhaseState[T any](phaseState any) *T`** — converts the shared `state any` into the typed struct of a specific phase.
- **Phase state** kept inside the session (`phaseState any`), so the Router does not know the details of the phase: it only calls the Handler and reacts to the `Result`.

### Dispatcher (server)

- The server exposes `dispatcher.Dispatcher(byteCode)` which, from a bytecode, returns the Handler of the corresponding phase (for now only `RegisterTokenReq` → registration handler).
- `Connection.AssignHandler` wires as the initial Handler a wrapper that resolves the dispatch on the first message and then replaces itself with the resolved Handler for the subsequent steps of the same session.
- Each phase has its own `CheckSize(tag, len)` to validate the payload length before processing it.

### Registration phases

Registration refactored as a **state machine** (previously it was a linear flow). The server maintains a `RegistrationServer` with states:

`stateAwaitRequest → stateAwaitNonce → stateAwaitSignature → stateCompleted | stateFailed`

- **stateAwaitRequest**: waits for the `RegisterTokenReq` bytecode; generates a per-session secret + random jump, sends the PoW (`PowToken`, serialized protobuf challenge).
- **stateAwaitNonce**: receives `ChallengeResponse` (8B big-endian nonce), verifies PoW; if valid it moves to waiting for the signature.
- **stateAwaitSignature**: receives `SignatureRequest` (blind point M', compressed 48B G1), signs blindly and returns `TokenEmission` (σ', 48B).
- The PoW level (and therefore the wait time `stateAwaitNonce → stateAwaitSignature`) is chosen based on the *server load*.

The client maintains a `RegistrationClient` with states:

`stateAwaitChallenge → stateAwaitToken → stateCompleted | stateFailed`

- **stateAwaitChallenge**: receives `PowToken`, decodes the challenge and solves it (`pow.Solve`); in parallel it creates the blind state (`CreateAndBlind`) and sends in one shot `ChallengeResponse` + `SignatureRequest` (nonce and M').
- **stateAwaitToken**: receives `TokenEmission`, removes the noise (`Unblind`) and obtains the unblinded token σ.

### Probe/anti-spam (server side)

- **`load_report`** has been made a pure function without circular dependencies: `Init(*atomic.Uint64)` connects the client counter, `LoadReport() (pow.Level, error)` maps `clientsNumber → Level` PoW (thresholds 50/150/300/500). The correct count of connected clients to initialize the atomic is still missing.
- **Server database BadgerDB** (`cmd/server/database`): `Init`, `GC` (interval that scales with load via `getTimeFromLoad`), `IsInitialized`, `CloseDB`. The GC adapts the VLog GC interval to the current PoW level (from 300s to 15s).
- **Blind signature** server (`network/blind_signature`): la coppia blind BLS è gestita dall'`atomic.Pointer[KeysBlindSignature]` `currentKeys` (privata in `memguard.Enclave`, pubblica in G2), inizializzata da `InitBlindSignature()`. `SignBlind(blindedPoint)` prende solo il punto e usa lo stato corrente (hash del pk corrente via `pkHash`); `Verify` fa il pairing check.
  - **Rotazione**: `RotateKey()` salva la chiave ritirata **in chiaro** su DB (`StoreBlindKey(pkHash, sk)` — chiave scaduta, non va cifrata), poi genera una nuova coppia. `GetPublicKeyByHash` cerca prima la chiave corrente, poi le ritirate su DB (`GetBlindKey` + `publicKeyFromPrivateBytes`, Y = x·G2) per la verifica di token vecchi.
  - `SerializeAndSave(token)` hashes e salva il token nel DB (`TokenDeduplication`) per impedirne il riuso.

### Complete registration flow (implemented)

La registrazione è divisa in **due fasi su stream yamux separati**: *token registration* e *bundle upload*.

**Token registration** (`Connection.TokenRegistration`, handler `token_registration`):
1. il client apre un nuovo stream yamux e invia `RegisterTokenReq` (0x01, payload vuoto)
2. il server (Dispatcher → registration handler) risponde con `PowToken` (0x02, challenge protobuf)
3. il client risolve il PoW e invia in un colpo solo `ChallengeResponse` (0x03, nonce) + `SignatureRequest` (0x04, M')
4. il server verifica la challenge (MAC + zero-bits) e firma M' alla cieca → `TokenEmission` (0x05, σ')
5. il client rimuove il rumore da σ' e ottiene il token finale, poi lo serializza in un `TokenVerification` e lo emette su **`GlobalOut`** per la fase successiva (consumato dall'orchestratore)

**Bundle upload** (`Connection.BundleUpload`, handler `bundlereg` — flusso client completo, lato server in costruzione):
- il client riceve il token dal `Local` chan (bytecode locale `RegistrationToken` 0xa1, iniettato dall'orchestratore via `PutRouter`) → invia `UploadBundleRequest` (0xa4) col `TokenVerification`
- attende `TokenConfirmation` (0xa5) → riceve il nickname dal `Local` (0xa2) → invia `NicknameRequest` (0xa6) → attende `NicknameResponse` (0xa7)
- se il nickname è disponibile riceve il bundle dal `Local` (0xa3), compone `UserBundle` (id_user = hash IK, nickname, public bundle, curve/KEM public sets) → invia `BundleUpload` (0xa8) → attende `BundleConfirmation` (0xa9)
- `Connection.BundleUpload` **non invia alcun messaggio all'apertura**: aspetta il token dal `Local` chan (la vecchia istruzione che mandava `RegisterTokenReq` è stata rimossa)

### Login implementation (2026-09-18)

Login is event-driven and has two deliberately different paths. A full login proves ownership of an already registered BundleID and pays a heavy PoW; after that proof the server blindly signs three independent one-use Pass Tokens. A quick login presents one Pass Token and is anonymous: it sends no BundleID and no ML-DSA/XEdDSA proof, so the server cannot link redemption to the full login that issued it.

The order is TLS/yamux → server identification → login. Production full login defaults to PoW Level5 (current preset: 128 MiB Argon2id, difficulty 11, expected roughly five minutes on the reference hardware) with a ten-minute response deadline. Solve time is probabilistic and hardware-dependent; this is a cost target, not a guaranteed minimum wall-clock delay. Identification still precedes PoW, so the flow does not prevent TCP, TLS or identification flooding.

Full login works as follows:

1. The client creates three random 64-byte messages and three independent BLS blinding factors, then sends the three 48-byte blinded points in `LoginStart`.
2. The server validates the three curve points and issues the Level5 PoW challenge.
3. After a valid solution the server returns a fresh login nonce.
4. The client signs a domain-separated message containing version, timestamp, serverID, TLS exporter binding, BundleID, nonce and all three blinded points with both its ML-DSA and X25519/XEdDSA identity keys.
5. The server loads `BundleID → UserBundle` from Badger, verifies both signatures and verifies that the points in the proof are byte-for-byte equal to those supplied before the PoW.
6. The server blindly signs all three points with the dedicated login BLS key, authenticates this full-login connection as the proven BundleID and returns the three blind signatures plus public-key metadata.
7. The client unblinds and verifies every signature, builds three independent `LoginToken` protobufs and stores them under the identified server in bbolt.

The login BLS key is separate from registration, memory-only and valid for a 24-hour signing epoch. Tokens contain the random message, unblinded signature, signing-key hash, epoch expiry and serverID. A server restart loses the login key and invalidates outstanding Pass Tokens.

Quick login works as follows:

1. The client loads one serialized Pass Token for the identified server and sends only `LoginTokenRedemption`.
2. The server verifies token fields, signing epoch and BLS signature.
3. The server calculates `SHA256("P2Chat/login-pass/v1" || serializedToken)` and passes it to `TokenDeduplication`.
4. A new hash is atomically stored as spent and the connection becomes authenticated anonymously. An existing hash is rejected.
5. The client deletes the local token after either acceptance or explicit rejection. Deleting a rejected token handles the case where the server consumed it but the earlier acceptance response was lost. When no tokens remain, the client performs another full login.

A quick-login connection has `Authed=true` and an `AuthenticatedUser` marked `Anonymous`; it is not inserted in `activeUsers[BundleID]`. Therefore a Pass Token is a bearer credential: possession is sufficient, the first valid redeemer wins, and the server learns no account identity from redemption. A full-login connection remains associated with the proven BundleID for that connection.

`LoginTokenRecord`, use counters, `ConsumeLoginToken` and the `login:tokens:` records have been removed. Three separately blinded one-use credentials replace one linkable three-use credential. The server never stores a serialized Pass Token, only its domain-separated hash in the existing token-deduplication database.

Login uses the existing byte-only Router. `Connection.Login()` opens a stream, assigns `login.Handler`, calls `Init` and injects `StartLogin`. The phase requests public parameters from the orchestrator, requests cancellable PoW solving and requests identity signatures; passwords and private keys remain outside phase state. `NotifyCompleted` has no counter: on full login it carries a serialized `LoginTokenBatch`, while on quick login it contains only the notification byte.

| Local bytecode | Direction | Meaning |
|---|---|---|
| StartLogin `0xc1` | Connection → Router | Start phase; Handler creates its state. |
| NotifyReady `0xc8` / Parameters `0xc4` | Phase → main / main → Router | binding32 + serverID32 + BundleID32 + fast flag1. |
| NotifyPassToken `0xc9` / PassToken `0xc5` | Phase → main / main → Router | Supply one serialized Pass Token. |
| NotifySolvePoW `0xca` / PoWSolution `0xc6` | Phase → main / main → Router | Challenge protobuf out; uint64BE solution back. |
| NotifySignProof `0xcb` / SignedProof `0xc7` | Phase → main / main → Router | Full-login signing message out; dual signatures back. |
| NotifyCompleted `0xc2` | Phase → main | Empty on quick success; followed by `LoginTokenBatch` on full success. |
| NotifyTokenRejected `0xc3` | Phase → main | The supplied Pass Token is invalid, expired or already spent. |

#### Client bbolt structure

The client database is `<project-root>/database.db`. It uses real nested bbolt buckets:

```text
servers
└── <ServerID:32>
    ├── identity       → MessagePack verified server identity
    ├── endpoint       → host:port
    ├── observed-ip    → latest numeric IP when available
    ├── login-bundle   → raw BundleID:32
    ├── pass-tokens
    │   ├── 0x01       → serialized LoginToken
    │   ├── 0x02       → serialized LoginToken
    │   └── 0x03       → serialized LoginToken
    └── users
        └── <nickname> → protobuf UserBundle

server:blacklist
└── <ServerID:32>      → MessagePack reason, endpoint and timestamp

private:bundles
└── <BundleID:32>
    ├── private-bundle → MessagePack PrivateBundle
    ├── curve-sets
    │   └── uint32BE(index) → serialized private curve set
    └── kem-sets
        └── uint32BE(index) → serialized private KEM set
```

`SavePassTokens` replaces the server's `pass-tokens` bucket atomically with exactly three entries. `LoadPassToken` returns the lowest remaining slot and `DeletePassToken` removes the acknowledged or rejected slot. Serialized Pass Tokens are bearer secrets and are currently stored as raw protobuf values in bbolt; protobuf serialization is not encryption.

#### Server Badger structure

Badger has no bucket hierarchy; both server stores are flat key:value namespaces organized by binary prefixes.

`<project-root>/data/database/` contains:

```text
"SERVER_IK"                                      → protobuf StoredServerIdentity
<BundleID:32>                                    → protobuf UserBundle
"nickname:" || nickname                         → BundleID:32
BundleID || ":curve:" || uint32BE(index)         → serialized public curve set
BundleID || ":kem:"   || uint32BE(index)         → serialized public KEM set
```

`<project-root>/data/token_db/` contains:

```text
"privateBlindKey"                               → encrypted registration blind key
<registration-token hash:32>                    → 0x01
SHA256("P2Chat/login-pass/v1" || LoginToken)     → 0x01
```

Registration-token and Pass-Token deduplication share the same physical Badger database. Pass Token hashes are domain-separated before entering the flat 32-byte keyspace. `TokenDeduplication` performs the presence check and insertion atomically under its existing mutex; no BundleID, token body, use counter or timestamp is stored for a spent Pass Token.

Tests cover three-token emission after PoW plus bundle proof, blind-signature verification, anonymous first redemption, rejection of token reuse and client bbolt token ordering/deletion. Tests inject Level1 so the suite remains fast; production defaults to Level5.

### Earlier access login and DDoS filtering proposal

> **Historical proposal, superseded by the implementation above.** In particular, its PoW-before-identification order, mandatory PoW on every reconnect and explicit first-contact approval do not describe the current code.

The current unauthenticated login phase would otherwise allow an arbitrary client to reach the server without proving either a computational cost or ownership of a registered bundle. The planned sequence is:

1. The client opens the TLS/yamux connection and requests an **access PoW** without sending a user identity or bundle ID.
2. The server issues a high-difficulty, MAC-authenticated PoW challenge. The challenge should be stateless or have strictly bounded short-lived state.
3. The client solves the PoW and sends the solution. The server rejects invalid solutions before ML-DSA signing, bundle lookups, or other costly operations.
4. After a valid PoW, the server performs **server identification**: it returns its persistent identity keys, server ID, and signatures bound to the client nonce and to the TLS exporter binding.
5. The client verifies and pins/trusts the server identity before revealing its own bundle ID or producing a login proof.
6. The server sends a fresh login nonce. The client replies with its `BundleID` and a proof of possession made with the identity key(s) of the already registered public bundle.
7. The server retrieves the public keys from its stored bundle for that `BundleID`, verifies the proof, and marks the current connection as authenticated.

The login proof must be domain-separated and bound to the exact context, for example:

```text
"P2Chat/login/v1" || serverID || TLSBinding || loginNonce || bundleID
```

The server must verify this signature only against the public identity keys stored in the registered bundle; it must not accept verification keys supplied by the client in the login request.

Authentication is connection-scoped rather than bearer-token-scoped. The server keeps an in-memory authentication context associated with the active TLS/yamux connection, containing at least `PoWVerified`, `Authenticated`, `BundleID`, login time, and the TLS binding. It is deleted when the connection closes or expires. A new connection must solve a new PoW and complete a new login, so access cannot be transferred by copying a token to another device or TLS connection.

For presence, the server will maintain an in-memory `ActiveUsers` registry keyed by authenticated `BundleID`, with the set of active connection IDs and `lastSeen`. A user is offline only when its last authenticated connection is removed. This registry is not persisted: a server restart terminates all TLS connections and therefore resets presence naturally.

Server trust on the client must be keyed primarily by the service endpoint/onion address and the cryptographic server identity, not by the observed IP address. An IP can change legitimately and is especially unsuitable as a trust anchor over Tor. A known endpoint presenting a different server identity is blocked by default; a previously unknown endpoint/identity requires explicit client-side trust/pinning. A confirmed malicious identity may be placed in the local client blacklist.

This design mitigates application-layer resource exhaustion, but does not itself prevent TCP/TLS handshake floods. The server still needs short TLS/phase deadlines, global connection and signature-work limits, and network-level rate limiting or onion-service exposure.


## Protocol message types

The bytecodes are now defined in the `phases` packages (`bytecodes.go`) on both the client and the server side.

| Byte | Name | Direction | Payload | Description |
|------|------|-----------|---------|-------------|
| `0x00` | DUMMY | Client → Server | random ≥1B | Dummy request for traffic obfuscation (padding). The server discards it without going through the Router. |
| `0x01` | REGISTER_TOKEN_REQ | Client → Server | 0B | Request for a registration token. Starts the blind signature flow. |
| `0x02` | POW_TOKEN | Server → Client | 56-65B | Proof-of-Work challenge (serialized protobuf challenge, `proto_struct_pow.Challenge`). |
| `0x03` | CHALLENGE_RESPONSE | Client → Server | 8B | Nonce (big-endian) that solves the PoW challenge. |
| `0x04` | SIGNATURE_REQUEST | Client → Server | 48B | Blind point M' (compressed affine G1) to sign. |
| `0x05` | TOKEN_EMISSION | Server → Client | 48B | Blind signature σ' (compressed affine G1); the client removes the noise and obtains σ. |
| `0xa4` | UPLOAD_BUNDLE_REQUEST | Client → Server | ≥1B | Avvia il bundle upload: payload = `TokenVerification` serializzato. |
| `0xa5` | TOKEN_CONFIRMATION | Server → Client | 1B | Conferma validità del token (1 = valido). |
| `0xa6` | NICKNAME_REQUEST | Client → Server | ≥1B | Richiesta disponibilità nickname. |
| `0xa7` | NICKNAME_RESPONSE | Server → Client | 1B | Disponibilità nickname (1 = disponibile). |
| `0xa8` | BUNDLE_UPLOAD | Client → Server | ≥1B | Payload `UserBundle` (id_user, nickname, public bundle, sets). |
| `0xa9` | BUNDLE_CONFIRMATION | Server → Client | 1B | Conferma accettazione bundle (1 = ok). |

> I bytecode locali del bundle handler (`Local` chan, non di rete) sono `RegistrationToken` 0xa1, `Nickname` 0xa2, `Bundle` 0xa3.


### Good and Force Close

during some tests with the connection for verify the execution of the token registration i notice from the LOG files a some particular type of errors :

```go 
[WARNING] Packet NOT received correctly EOF            ← 1
[ERROR]   error: session listener closed, ID: 1 EOF    ← 2
[WARNING] force closing session, ID: 1                 ← 3
[ERROR]   data transmission error                      ← 4
[ERROR]   error writing message data transmission error ← 5
```

this happened after the token registration request phase and was strange because it all was did correctly
but after i realized that i had planned a `Close()` function that closed all the process of the session in the case that should accour some problem or errors so when the phase was completed the use of `Close()` forced the closing of the session create some problem for
- Outgoing chan still NOT empty
- Listener closed with force
so i separate the Close functino in `GoodClose()` and `ForceClose()` where the first must be used for graceful closing and the second used when some problems or error occour in the session

now the phase doesnt create any error 

PS i did this modify also in the server 


### Parallelism and Benchmark about the bundle creation

i created a test `BenchmarkCreateBundleAndSets()` that measure how much time my computer (macbook pro M4) needs to create the whole bundle and all the sets, the time suprise me, infact took only about 350ms
```
BenchmarkCreateBundleAndSets
    bundle_test.go:206: timer bundle creation:  389.588084ms
    bundle_test.go:207: timer marshal        :  209.791µs
    bundle_test.go:206: timer bundle creation:  368.264625ms
    bundle_test.go:207: timer marshal        :  174.375µs
    bundle_test.go:206: timer bundle creation:  338.60425ms
    bundle_test.go:207: timer marshal        :  171.25µs
    bundle_test.go:206: timer bundle creation:  331.387458ms
    bundle_test.go:207: timer marshal        :  210.875µs
    bundle_test.go:206: timer bundle creation:  349.668209ms
    bundle_test.go:207: timer marshal        :  185.75µs
    bundle_test.go:206: timer bundle creation:  340.247833ms
    bundle_test.go:207: timer marshal        :  186.834µs
    bundle_test.go:206: timer bundle creation:  340.911708ms
    bundle_test.go:207: timer marshal        :  156.417µs
    bundle_test.go:206: timer bundle creation:  405.883125ms
    bundle_test.go:207: timer marshal        :  133.75µs
    bundle_test.go:206: timer bundle creation:  338.898083ms
    bundle_test.go:207: timer marshal        :  139.667µs
    bundle_test.go:206: timer bundle creation:  331.474834ms
    bundle_test.go:207: timer marshal        :  185.916µs
    bundle_test.go:206: timer bundle creation:  334.876708ms
    bundle_test.go:207: timer marshal        :  242.167µs
    bundle_test.go:206: timer bundle creation:  325.108167ms
    bundle_test.go:207: timer marshal        :  194.291µs
    bundle_test.go:206: timer bundle creation:  320.954958ms
    bundle_test.go:207: timer marshal        :  184.75µs
    bundle_test.go:206: timer bundle creation:  322.752333ms
    bundle_test.go:207: timer marshal        :  197.5µs
    bundle_test.go:206: timer bundle creation:  328.939666ms
    bundle_test.go:207: timer marshal        :  193.917µs
    bundle_test.go:206: timer bundle creation:  338.078791ms
    bundle_test.go:207: timer marshal        :  179.042µs
    bundle_test.go:206: timer bundle creation:  337.66725ms
    bundle_test.go:207: timer marshal        :  207.542µs
    bundle_test.go:206: timer bundle creation:  326.526583ms
    bundle_test.go:207: timer marshal        :  176.416µs
    bundle_test.go:206: timer bundle creation:  327.778959ms
    bundle_test.go:207: timer marshal        :  267.166µs
```

this is the benchmark repeated `b.N` times (for more accuracy, automatic in GO)

this make me think about the real gain of paralelization and real benefits for the application
the idea was infact start (in goroutiness) the bundle creation before the initialization of another session with yamux with the server for seding the bundle

this result make me thought about the benefits and my conclusions was that 0.35 ms is so a short time and so an implementation for create a parallelis for bundle sending and bundle creation could be overkill but i will implement a solution which can still support and implement parallisation for future feature that i will implement and that will benefit of this implementation

### Commitment Scheme Flow & Bundle Verification (2026-09-21)

To protect against key substitution attacks (e.g. a malicious server or Man-In-The-Middle replacing public identity keys in the user bundle), the protocol provides a cryptographic **Commitment Scheme** based on an out-of-band shared secret (pre-shared password):

#### 1. Creation flow (Bundle Owner / Sender)
1. **Password selection**: The user selects a password/passphrase and shares it with the intended contact through an out-of-band, secure channel (off the wire).
2. **KDF derivation (Argon2id)**: The sender derives the Pre-Shared Key (PSK, 64 bytes) using Argon2id with default high security level (`Level 3`: Time=6, Memory=1GB, Threads=NumCPU) and a fresh 32-byte salt (`HashWithArgon` / `CreateArgonParams`).
3. **Commitment creation (`Commitment(...)`)**:
   - The PSK buffer is used as the key for a **BLAKE2b-256** keyed hash over:
     - Domain separator (`P2Chat/commitment/v1`)
     - Random 32-byte nonce
     - ML-DSA-87 public identity key bytes
     - X25519 public identity key bytes
   - The computed commitment hash is dual-signed by the sender's identity keys:
     - Signed with `ML-DSA-87` (using context `"commitment_scheme_mldsa"`)
     - Signed with `X25519` (via XEdDSA)
   - The output is organized into:
     - `CommitmentSchemeUpload` (public payload attached to the user bundle): contains the commitment hash, both signatures, the nonce, and the public `ArgonParams` (including the salt and level).
     - `CommitmentSchemePrivate` (local/private storage): wraps the upload scheme and stores the PSK encrypted with `keyencryption.Encrypt` (password- or HSM-backed) to be saved in the client's private database.

#### 2. Verification flow (Bundle Recipient)
1. **Bundle retrieval**: The recipient downloads the contact's bundle from the server, which contains `CommitmentSchemeUpload` and the public identity keys (ML-DSA and X25519).
2. **Deriving the matching KDF**: The recipient enters the same password shared out-of-band. Using the `salt` from the bundle's `ArgonParams` and the predefined default Argon2id level (`Level 3`), the recipient executes `DeriveWithArgon` to reconstruct the exact same 64-byte PSK in protected memory (`*memguard.LockedBuffer`).
3. **Commitment verification (`VerifyCommitment(...)`)**:
   - Recomputes the expected BLAKE2b-256 hash using the recipient-derived PSK, the nonce from the bundle, and the public identity keys from the bundle.
   - Compares the expected hash with the bundle's commitment using constant-time comparison (`hmac.Equal`).
   - Verifies the ML-DSA signature over the commitment hash against the bundle's ML-DSA public key.
   - Verifies the X25519/XEdDSA signature over the commitment hash against the bundle's X25519 public key.

#### 3. Verification decision
- **Valid (Match)**: If the commitment hash matches AND both identity signatures are valid, the bundle is confirmed authentic. The identity keys legitimately belong to the expected user, completely ruling out server-side key replacement or MITM. The identity keys can then be safely pinned and trusted locally.
- **Invalid (Mismatch / Error)**: If the password differs, if the commitment hash does not match, or if either signature fails verification, the bundle is immediately rejected as compromised or untrusted.
