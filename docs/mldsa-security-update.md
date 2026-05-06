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

