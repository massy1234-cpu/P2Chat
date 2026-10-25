# P2Chat: architettura attuale e stato di avanzamento

> Fotografia tecnica del repository al 27 settembre 2026.
>
> Questo documento descrive il codice attualmente presente nel working tree. Quando differisce da note storiche, tabelle di avanzamento o vecchie sezioni di `docs/recap.md`, prevale il comportamento verificabile nel codice corrente.

## 1. Scopo del progetto

P2Chat è un sistema di messaggistica orientato alla privacy che combina:

- connessione del client attraverso Tor;
- TLS 1.3 con preferenza per lo scambio ibrido X25519 + ML-KEM-768;
- autenticazione applicativa del server, separata dal certificato TLS;
- multiplexing di più protocolli applicativi sulla stessa connessione tramite yamux;
- identità utente basate su ML-DSA-87 e X25519/XEdDSA;
- bundle PQXDH con prekey classiche e post-quantum;
- registrazione protetta da Proof of Work e token con firma cieca;
- login completo con Proof of Work e prova delle identity key;
- login rapido anonimo tramite pass token monouso;
- gestione dei segreti in memoria tramite `memguard`;
- valutazione locale della robustezza della password tramite una piccola CNN Python distribuita come eseguibile PyInstaller.

Il sistema non è ancora una chat completa pronta per l'uso. Il nucleo oggi più maturo copre trasporto, identificazione del server, registrazione dell'identità, login e download dei bundle pubblici. La messaggistica end-to-end, la gestione delle sessioni crittografiche tra utenti, la riconnessione automatica e il collegamento con la UI Tauri devono ancora essere completati.

## 2. Stato sintetico

| Area | Stato attuale | Nota |
|---|---|---|
| Avvio server e database | Implementato | Password server, identità, chiavi blind, TLS listener e GC Badger |
| Tor client | Implementato | Avvio Tor embedded e connessione al server |
| TLS 1.3 ibrido | Implementato | `X25519MLKEM768`, fallback/preferenza secondaria `X25519` |
| Binding TLS applicativo | Implementato | Exporter di 32 byte usato in identificazione e login |
| Identificazione server | Implementata | Doppia firma, TOFU, pin per endpoint e blacklist |
| Registrazione token | Implementata | PoW adattiva + firma cieca BLS |
| Generazione bundle PQXDH | Implementata | Identity key, signed prekey, last-resort KEM e one-time set |
| Commitment condiviso | Implementato | Argon2id, BLAKE2b-256 e doppia firma |
| Upload bundle | Implementato | Token monouso, nickname riservato, challenge firmata e salvataggio atomico |
| Login completo | Implementato | PoW, nonce fresco, prova ML-DSA/XEdDSA e tre pass token |
| Login rapido | Implementato | Un pass token monouso; fallback al login completo se rifiutato |
| Catalogo nickname | Implementato | Esportazione server, ricezione client e cache bbolt |
| Download bundle privato | Implementato | Richiesta target + due decoy, esattamente tre nickname |
| Classificatore password | Integrato | Usato solo durante la nuova registrazione; password deboli rifiutate |
| Logging | Implementato, migliorabile | Tutti i livelli su file; warning su stdout; errori su stdout e stderr |
| Presenza utenti | Parziale | Solo RAM sul server; nessuna persistenza |
| Chat e cifratura messaggi | Non implementate | Non esiste ancora il flusso applicativo completo di messaggistica |
| Consumo delle one-time prekey | Non completato | I set sono salvati, ma manca il protocollo completo di prelievo/rotazione |
| Riconnessione automatica | Non implementata | La perdita della connessione termina il flusso corrente |
| UI Tauri ↔ backend Go | Non collegata | La UI è attualmente un prototipo visuale con dati statici/mock |
| Packaging finale | Non completato | Il classificatore è un bundle macOS locale e i path dipendono dal repository |

## 3. Vista generale del sistema

```text
┌──────────────────────── CLIENT ────────────────────────┐
│                                                       │
│  CLI / futuro bridge Tauri                            │
│          │                                            │
│          ▼                                            │
│  main.go: orchestrazione, password, credenziali       │
│          │                                            │
│          ▼                                            │
│  Connection + SingleSession + phase handlers          │
│          │                                            │
│          ▼                                            │
│  framing applicativo + padding + checksum             │
│          │                                            │
│          ▼                                            │
│  yamux → TLS 1.3 → Tor                                │
└─────────────────────────┬─────────────────────────────┘
                          │ rete
┌─────────────────────────▼─────────────────────────────┐
│                       SERVER                          │
│                                                      │
│  TLS listener → yamux server → Connection            │
│          │                                           │
│          ▼                                           │
│  dispatcher per bytecode → phase handler             │
│          │                                           │
│          ├── identificazione server                  │
│          ├── registrazione token                     │
│          ├── upload bundle                           │
│          ├── login                                   │
│          ├── catalogo nickname                       │
│          └── acquisizione bundle                     │
│                                                      │
│  Badger principale + Badger token + presenza in RAM  │
└──────────────────────────────────────────────────────┘
```

La distinzione più importante è questa:

- `main.go` del client è l'orchestratore e possiede le decisioni di alto livello;
- le fasi di rete sono macchine a stati deterministiche;
- la sessione trasporta messaggi tra rete, handler di fase e orchestratore;
- password e chiavi private non devono diventare stato generico della fase.

## 4. Struttura del repository realmente rilevante

```text
P2Chat/
├── cmd/client/
│   ├── main.go                         orchestratore CLI
│   ├── database/                       database locale bbolt
│   ├── cirl-custom/                    fork CIRCL con supporto memguard
│   └── internals/
│       ├── argon/                      Argon2id e preset
│       ├── cnn_password/               bridge Go → classificatore Python
│       ├── commitment/                 commitment condiviso
│       ├── encryption/                 AES-GCM e protezione chiavi
│       ├── HSM/                        Secure Enclave e TPM
│       ├── keys/                       ML-DSA, ML-KEM, X25519
│       ├── network/                    Tor, TLS, yamux, sessioni e fasi
│       ├── p2log/                      log su file/console
│       ├── proto/                      sorgenti Protobuf
│       ├── proto_generated/            codice Protobuf generato
│       ├── protocol/pqxdh/             costruzione dei bundle
│       └── storage/                    risoluzione root e directory dati
├── cmd/server/
│   ├── main.go                         avvio e arresto del server
│   ├── database/                       persistenza Badger
│   └── internals/
│       ├── ID_server/                  identità applicativa server
│       ├── PQXDH/                      verifica bundle
│       ├── keys/                       verifica firme
│       ├── network/                    bootstrap, dispatcher e fasi
│       └── nicknameExposure/           catalogo nickname in memoria
├── password_cnn/                       sorgenti, training e build Python
├── P2Chat-UI/                          frontend React/Tauri
├── data/                               chiavi, Tor, log e DB server
├── database.db                         DB bbolt del client
├── docs/
├── go.mod
└── Makefile
```

Esistono ancora artefatti storici o di build nel repository. Per il server, il percorso canonico corrente è `cmd/server/internals/network`, non eventuali vecchie copie o descrizioni di `cmd/server/network`.

## 5. Regole architetturali da preservare

### 5.1 Il client `main` è l'orchestratore

Il client `main.go` deve continuare a occuparsi di:

- apertura della connessione;
- identificazione del server;
- scelta tra login e registrazione;
- lettura delle password dal terminale;
- accesso alle identity key private;
- soluzione del PoW quando la fase lo richiede;
- firma delle challenge;
- consumo degli eventi prodotti dalle fasi;
- salvataggio delle associazioni locali e dei pass token;
- decisioni di retry e fallback.

Queste responsabilità non vanno spostate dentro `Connection.Login()` o nello stato della fase login.

### 5.2 Le fasi non leggono direttamente dalla UI

Una fase riceve solo:

- un bytecode;
- un payload binario;
- un puntatore allo stato privato della fase.

La funzione ritorna un `Result` contenente:

```go
type Result struct {
    IntoWire     [][]byte
    NextDeadline time.Duration
    Completed    bool
    CloseStream  bool
    Err          error
    Events       [][]byte
}
```

Il significato dei campi è:

- `IntoWire`: messaggi da inviare al peer;
- `Events`: notifiche o dati destinati all'orchestratore locale;
- `NextDeadline`: timeout del prossimo stato;
- `Completed`: la fase è terminata correttamente;
- `CloseStream`: la sessione deve essere abortita;
- `Err`: errore della macchina a stati.

### 5.3 Due ingressi, un solo Router

La sessione client possiede due ingressi:

- `Incoming`: messaggi arrivati dalla rete;
- `Local`: eventi inseriti dall'orchestratore.

Entrambi passano attraverso lo stesso `Router` e lo stesso handler. Questo evita di duplicare la macchina a stati.

```text
rete ──► Incoming ─┐
                   ├──► Router ──► Handler ──► IntoWire / Events
main ──► Local ────┘
```

- `PutRouter(bytecode, payload)` inserisce un evento locale.
- `PutOutgoing(data)` invia direttamente un messaggio già formato alla rete.

### 5.4 Lo stato nasce dentro la fase

Quando `phaseState` è `nil`, l'handler crea la propria struttura concreta. La `Connection` non deve costruire in anticipo lo stato delle normali fasi client. L'eccezione pratica sul server è l'iniezione del contesto strettamente legato alla connessione, per esempio binding TLS e callback di autenticazione nel login.

### 5.5 Timeout

`FillResult` applica 30 secondi se non viene indicato un timeout diverso. Il PoW può usare tempi più lunghi, fino a `MaxWaitTime()` o dieci minuti sul client login. Ogni nuovo stato di attesa deve avere una scadenza, altrimenti una sessione half-open può trattenere memoria sul server senza limite.

## 6. Avvio del server

L'avvio parte da `cmd/server/main.go`:

1. verifica che `stdin` sia un terminale;
2. legge la password del server senza echo;
3. trasferisce la password in un `memguard.Enclave`;
4. chiama `ServerStart("0.0.0.0", 9000, password)`;
5. avvia il garbage collector periodico di Badger;
6. installa il watchdog per `SIGINT` e `SIGTERM`;
7. lascia l'accept loop in esecuzione.

`ServerStart` inizializza in ordine:

1. database Badger principale;
2. catalogo nickname in memoria;
3. identity key del server;
4. chiavi per la firma cieca di registrazione;
5. registro dei client e misurazione del carico;
6. certificato TLS autofirmato;
7. listener TLS 1.3;
8. accept loop dei client.

Il server preferisce le curve TLS:

```go
[]tls.CurveID{
    tls.X25519MLKEM768,
    tls.X25519,
}
```

Alla chiusura vengono fermati listener e client, chiusi i database e purgata la memoria protetta da `memguard`.

## 7. Avvio del client

Il flusso corrente del client è:

1. parsing delle flag `-server`, `-port` e `-bundle`;
2. apertura di `database.db` con bbolt;
3. inizializzazione di Tor;
4. apertura del collegamento Tor verso il server;
5. handshake TLS 1.3 sopra Tor;
6. derivazione del TLS exporter di 32 byte;
7. creazione della sessione yamux client;
8. avvio del watchdog;
9. identificazione applicativa del server;
10. caricamento dell'eventuale bundle locale associato al server;
11. menu CLI: login, registrazione oppure uscita;
12. dopo il login, menu autenticato per il download di un bundle utente.

Non esiste ancora un ciclo di riconnessione automatica. Se Tor, TLS o yamux cadono, `Connection.Done` viene chiuso e il flusso corrente termina.

## 8. Stack di rete

### 8.1 Tor

Il client usa `github.com/cretz/bine/tor` per avviare e controllare Tor. Il processo Tor vive oltre il solo timeout di bootstrap; il timeout limita l'abilitazione iniziale della rete, non la vita della connessione.

### 8.2 TLS

Il client configura TLS con `InsecureSkipVerify: true`. Questo significa che il certificato TLS autofirmato non è la radice di fiducia dell'identità del server. La fiducia viene invece stabilita dalla fase applicativa di identificazione descritta più avanti.

Dopo l'handshake entrambi i lati derivano:

```text
ExportKeyingMaterial("EXPORTER-Channel-Binding", nil, 32)
```

Il risultato è specifico della connessione TLS e non viene persistito. Viene incluso nelle firme di identificazione e login, legando quelle prove al canale corrente.

### 8.3 yamux

Una connessione TLS contiene una sessione yamux. Ogni protocollo applicativo apre un nuovo stream:

- identificazione server;
- richiesta token di registrazione;
- upload bundle;
- login;
- disponibilità bundle;
- catalogo nickname;
- download bundle.

Il server limita ogni connessione a dieci stream simultanei tramite `SessionStop`. Il registro globale assegna inoltre un ID a ogni client collegato.

### 8.4 Framing applicativo

Ogni messaggio applicativo è incapsulato in:

```text
┌──────────────┬────────────┬──────────────────────────────┬─────────────────────┐
│ totalSize 4B │ padLen 2B  │ SHA-256 payload reale 32B   │ payload + padding   │
└──────────────┴────────────┴──────────────────────────────┴─────────────────────┘
```

Dettagli:

- header fisso di 38 byte;
- `totalSize` include payload reale e padding, ma non l'header;
- il checksum copre solo il payload reale;
- padding casuale tra 250 e 749 byte;
- limite di lettura `MaxMessageSize = 64 KiB`;
- read deadline di dieci minuti;
- write deadline di trenta secondi;
- primo byte del payload reale = bytecode/tag della fase.

Il checksum rileva corruzione o manomissione accidentale, ma non sostituisce TLS come meccanismo di autenticità.

### 8.5 Dummy traffic e jitter

Il client genera dummy message con tag `0x00` ogni 400–1399 ms. La dimensione segue l'ultimo messaggio reale, con variazione approssimativa di ±250 byte e minimo 32 byte. Il server scarta i dummy prima del dispatcher.

Prima degli invii viene applicato un ritardo casuale di 200–699 ms. Questo riduce la regolarità più evidente del traffico, ma non costituisce da solo una difesa completa contro l'analisi del traffico.

## 9. Connection e SingleSession

### 9.1 Client

`Connection` contiene:

- endpoint configurato;
- `ServerID` verificato;
- sessione yamux principale;
- mappa concorrente delle sessioni attive;
- pool di ID riutilizzabili;
- canali di chiusura.

Ogni `SingleSession` client avvia quattro goroutine:

- `Listener`: legge frame e alimenta `Incoming`;
- `Writer`: aggiunge framing e scrive sulla rete;
- `dummyRequests`: produce traffico dummy;
- `Router`: applica la macchina a stati.

Capacità correnti dei canali:

| Canale | Capacità | Produttore → consumatore |
|---|---:|---|
| `Incoming` | 128 | Listener → Router |
| `Outgoing` | 128 | Router/orchestratore → Writer |
| `Local` | 64 | orchestratore → Router |
| `Events` | 64 | Router → orchestratore |

### 9.2 Server

Il server accetta gli stream yamux e assegna inizialmente un handler-dispatcher generico. Il primo bytecode seleziona la fase registrata. In seguito la sessione usa direttamente l'handler scelto.

Il dispatcher è popolato tramite `init()` dei package importati con blank import in `cmd/server/main.go`. Aggiungere un handler sul disco non basta: il relativo package deve essere importato, altrimenti la registrazione non viene eseguita.

Prima di scegliere la fase, `Connection.AssignHandler` applica i vincoli di accesso:

- identificazione server e registrazione sono consentite prima del login;
- un login richiede che la connessione sia già identificata;
- è consentito un solo login simultaneo per connessione;
- catalogo, disponibilità e acquisizione bundle ricevono lo stato di autenticazione;
- gli altri bytecode richiedono autenticazione.

## 10. Mappa dei bytecode di rete

| Intervallo/tag | Protocollo |
|---|---|
| `0x00` | dummy traffic |
| `0x01`–`0x07` | token di registrazione e PoW |
| `0x08`–`0x09` | identificazione server |
| `0x0a`–`0x12` | login completo/rapido |
| `0xa4`–`0xaa` | registrazione e upload bundle |
| `0xb1`–`0xb5` | acquisizione/disponibilità bundle |
| `0xb6`–`0xb8` | catalogo nickname |

I bytecode `0xc1` e successivi usati dal client login, `0xf1` e `0xf2` usati dalle fasi di catalogo/bundle e `0xa1`–`0xa3`/`0xab` usati dall'upload sono eventi locali. Non attraversano la rete: vengono inseriti con `PutRouter`.

## 11. Identificazione applicativa del server

Questa fase viene eseguita su ogni nuova connessione, prima del login o della registrazione.

### 11.1 Flusso

1. Il client genera un nonce casuale di 32 byte.
2. Invia il nonce al server.
3. Il server costruisce il messaggio:

   ```text
   versione P2Chat || nonce client || TLS exporter binding
   ```

4. Il server firma il messaggio con:

   - ML-DSA-87;
   - la firma Ed25519 derivata dalla identity key X25519 usata dal progetto.

5. Il server restituisce versione, chiavi pubbliche, firme e `ServerID`.
6. Il client ricalcola:

   ```text
   ServerID = SHA-256(PubMLDSA || PubX25519)
   ```

7. Il client verifica dimensioni, hash e entrambe le firme.
8. Solo dopo la verifica aggiorna la fiducia locale.

### 11.2 TOFU, pin e blacklist

Il comportamento è Trust On First Use:

- prima osservazione: salva identità, endpoint e IP osservato;
- stesso endpoint e stessa identità: accetta;
- stessa identità verificata a un endpoint diverso: aggiorna l'indirizzo e segnala il cambiamento;
- stesso endpoint ma nuova identità: rifiuta e inserisce la nuova identità in blacklist;
- identità già in blacklist: rifiuta.

Il codice corrente confronta anche byte per byte le chiavi pubbliche deserializzate dall'identità salvata quando il `ServerID` coincide. Questo impedisce di accettare silenziosamente una struttura locale incoerente con lo stesso ID.

## 12. Registrazione di un nuovo utente

La registrazione completa è composta da più fasi indipendenti.

```text
password locale
    │
    ├── controllo minimo 16 byte
    └── CNN: Debole? ── sì ──► richiedi nuova password
              │ no
              ▼
token registration (PoW + blind signature)
              ▼
creazione locale bundle PQXDH + commitment
              ▼
upload: token → nickname → challenge firmata → bundle
              ▼
salvataggio associazione server ↔ bundle locale
```

### 12.1 Password di registrazione

La password:

- viene letta con `term.ReadPassword`, quindi senza echo;
- deve avere almeno 16 byte;
- viene immediatamente spostata in memoria `memguard`;
- viene classificata localmente;
- viene rifiutata se la classe è `Debole`;
- viene accettata se la classe è `Media` o `Forte`.

La soglia è in byte, non in caratteri Unicode. Sedici caratteri ASCII sono sedici byte; un carattere Unicode può occupare più byte. Al momento il progetto non impone un alfabeto ASCII unico tra validazione Go e tokenizer Python.

Durante il login di un'identità già creata la CNN non viene rieseguita. Questo è intenzionale: cambiare modello o soglie in futuro non deve impedire l'accesso a una password già usata per cifrare le chiavi.

### 12.2 Token di registrazione

Il client apre una fase `TokenRegistration`:

1. invia `RegistrationStart`;
2. il server sceglie un livello PoW in base al carico;
3. il server emette una challenge Argon2id autenticata;
4. il client risolve la challenge;
5. il client crea un messaggio casuale e lo acceca;
6. invia soluzione PoW e punto accecato;
7. il server verifica il PoW e firma il punto senza conoscere il messaggio originale;
8. il client rimuove l'accecamento;
9. il token risultante viene emesso su `Events` verso l'orchestratore.

Il token è successivamente consumato dalla fase di upload bundle. Il server ne registra l'uso per impedire un secondo upload con lo stesso token.

### 12.3 Creazione del bundle PQXDH

`InitializePQXDH` crea e salva localmente:

- identity key ML-DSA-87;
- identity key X25519;
- signed prekey X25519;
- last-resort ML-KEM-768;
- firme di autenticazione delle prekey;
- one-time curve set;
- one-time KEM set;
- commitment pubblico e materiale privato locale.

Nel flusso CLI corrente vengono richiesti due set per tipo. Le chiavi private vengono cifrate prima della persistenza. `useHSM` è oggi `false` nel flusso principale, anche se esistono implementazioni Secure Enclave e TPM.

### 12.4 Commitment condiviso

Il commitment permette a due persone che condividono un segreto fuori banda di verificare che il bundle scaricato corrisponda davvero al proprietario atteso.

Il valore pubblico usa:

```text
BLAKE2b-256(
    "P2Chat/commitment/v1" ||
    nonce ||
    public ML-DSA ||
    public X25519 ||
    Argon2id(shared secret)
)
```

Il valore viene firmato con entrambe le identity key. Sul server vengono caricati solo:

- commitment da 32 byte;
- nonce da 32 byte;
- parametri Argon2id e salt;
- firma ML-DSA;
- firma XEdDSA.

Il segreto condiviso deve avere almeno 16 byte. Questo non significa che hash, nonce o salt siano stati ridotti: rimangono tutti a 32 byte. La parte privata conserva localmente il segreto cifrato e i parametri necessari a decifrarlo.

### 12.5 Upload del bundle

L'upload segue questa sequenza:

1. il client passa localmente alla fase il token ottenuto;
2. la fase lo inoltra al server;
3. il server verifica firma e unicità del token;
4. il client invia il nickname;
5. il server valida il nickname e lo riserva atomicamente per cinque minuti;
6. il server genera `originalM`, una challenge casuale di 32 byte;
7. l'orchestratore apre le identity key private e firma `originalM` con entrambe;
8. la fase riceve localmente le firme;
9. il client invia bundle pubblico, firme e set pubblici;
10. il server verifica commitment, BundleID, unicità e firme;
11. il server salva bundle, mapping nickname e prekey in una transazione;
12. il server aggiorna il catalogo nickname;
13. il client salva l'associazione tra server e bundle locale.

Il server accetta nickname composti da 5–15 byte ASCII tra lettere, numeri e underscore.

## 13. Login

`Connection.Login()` non riceve credenziali. Apre uno stream, assegna direttamente `login.Handler`, avvia la sessione, inserisce l'evento locale `StartLogin` e restituisce sessione ed `Events`.

Le credenziali restano nell'orchestratore.

### 13.1 Parametri comuni

L'orchestratore costruisce 97 byte:

```text
TLS binding 32B || ServerID 32B || BundleID 32B || fast flag 1B
```

### 13.2 Login completo

Il login completo avviene quando non è disponibile un pass token valido:

1. il client genera tre messaggi casuali e tre richieste cieche;
2. invia le tre richieste al server;
3. il server sceglie il livello PoW in base al carico;
4. il server invia la challenge;
5. l'orchestratore risolve il PoW, con attesa massima lunga;
6. il server verifica la soluzione;
7. il server genera nonce, timestamp e versione;
8. il client costruisce una prova legata a:

   ```text
   ServerID + TLS binding + BundleID + nonce + timestamp + versione + richieste cieche
   ```

9. l'orchestratore firma la prova con ML-DSA e XEdDSA;
10. il server carica il bundle registrato e verifica entrambe le firme;
11. la connessione viene autenticata con il BundleID;
12. il server firma alla cieca le tre richieste;
13. il client rimuove l'accecamento, verifica le firme e costruisce tre pass token;
14. i tre token vengono salvati nel bucket del server.

Le chiavi di firma dei pass token sono separate dalle chiavi dei token di registrazione. Sono solo in memoria e scadono dopo 24 ore. Un riavvio del server le invalida.

### 13.3 Login rapido

Il client carica un token alla volta dal database:

1. apre il token in memoria protetta;
2. lo invia al server;
3. il server verifica key hash, scadenza e firma;
4. calcola un hash con dominio `P2Chat/login-pass/v1`;
5. registra atomicamente il token nel database di deduplicazione;
6. se non era già presente, autentica la connessione in modalità anonima;
7. il client elimina lo slot locale consumato.

Se il server rifiuta il token, il client elimina comunque lo slot e tenta il successivo; dopo l'esaurimento passa al login completo. Sono previsti al massimo quattro tentativi complessivi nel ciclo corrente.

Il login rapido è anonimo dal punto di vista dello stato server: dimostra il possesso di un token valido, ma non associa `AuthenticatedUser` a un BundleID. Questo consente accesso alle operazioni protette che controllano il flag di autenticazione, senza rivelare al server quale bundle abbia ottenuto originariamente il token.

## 14. Download di un bundle utente

Questa funzione è disponibile solo dopo il login.

### 14.1 Catalogo nickname

Il client prova prima a usare il catalogo salvato nel proprio database. Se il target non è presente o il catalogo non ha abbastanza nickname distinti, richiede al server il catalogo aggiornato e lo salva come JSON.

La fase server accetta la richiesta solo da una connessione autenticata e attende una conferma prima di chiudere lo stream.

### 14.2 Privacy tramite decoy

Una richiesta bundle contiene sempre esattamente tre nickname distinti:

- il target reale;
- due nickname decoy casuali;
- ordine finale mescolato con `crypto/rand`.

Il server restituisce tre bundle pubblici. Il client verifica che la risposta contenga esattamente i nickname richiesti e seleziona il target localmente.

Con meno di tre utenti distinti registrati questa proprietà non è realizzabile. Per questo il client produce l'errore:

```text
the server catalog does not contain enough nicknames for a private bundle request
```

Non è un problema di fase mancante: la fase è implementata. È un requisito della strategia target + due decoy. In un ambiente di test occorrono almeno tre nickname registrati.

### 14.3 Verifica del commitment

Prima di salvare il bundle, il client:

1. valida forma e dimensioni del commitment pubblico;
2. chiede all'utente il segreto condiviso;
3. ricalcola Argon2id con i parametri pubblicati;
4. ricalcola il commitment;
5. verifica la firma ML-DSA;
6. verifica la firma XEdDSA;
7. salva il bundle con un flag locale autenticato/non autenticato.

Il server non conosce il segreto condiviso e non può eseguire questa verifica al posto del client.

## 15. Modello crittografico e tipi di chiave

### 15.1 ML-DSA-87

Usata per firme post-quantum:

- identity key utente;
- identity key server;
- firme delle challenge di registrazione e login;
- firme del commitment;
- autenticazione delle prekey del bundle.

### 15.2 ML-KEM-768

Usata per il lato post-quantum dei bundle e dal TLS ibrido supportato dalla versione Go in uso. Un shared secret ML-KEM non deve essere usato direttamente come chiave AES: va prima processato da una KDF.

### 15.3 X25519 e firma derivata

X25519 viene usata per ECDH. Il progetto usa inoltre la conversione fornita da `go.step.sm/crypto/x25519` per produrre/verificare firme Ed25519 derivate dalla chiave X25519. Nel codice e nei log questa costruzione è chiamata XEdDSA.

### 15.4 Blind signature

Le firme cieche BLS12-381 servono a separare:

- prova di costo durante la registrazione;
- successivo uso del token;
- emissione dei pass token durante il login completo;
- successivo login rapido anonimo.

Il server firma punti accecati e non vede il messaggio finale che il client userà come token.

## 16. Gestione dei segreti in memoria

Convenzioni del progetto:

- `*memguard.Enclave`: segreto cifrato in memoria quando non è in uso;
- `*memguard.LockedBuffer`: segreto aperto temporaneamente in memoria bloccata;
- `[]byte`: solo dati pubblici, ciphertext, hash, nonce e firme.

La password viene letta in un normale slice restituito dal terminale, copiata immediatamente in un buffer `memguard`, azzerata e sigillata. Quando occorre usarla, l'enclave viene aperta per il tempo minimo necessario e il buffer viene distrutto.

Limite importante: il classificatore è un processo Python separato. Per passargli la password, Go apre temporaneamente l'enclave e collega quei byte allo `stdin` del figlio. Python non offre qui le stesse garanzie `mlock` di `memguard`; quindi il classificatore aumenta temporaneamente la superficie di esposizione locale. La password non viene però passata come argomento di comando, non compare nella command line e non viene inclusa nel JSON di risposta.

## 17. Classificatore CNN delle password

### 17.1 Organizzazione

Ci sono due aree distinte:

- `password_cnn/`: training, dataset, script Python, pesi e output PyInstaller;
- `cmd/client/internals/cnn_password/`: integrazione Go e bundle eseguibile usato dal client.

Il file Go risolve attualmente il percorso:

```text
<ProjectRoot>/cmd/client/internals/cnn_password/neuralNetwork/password-classifier
```

Avvia l'eseguibile, imposta come working directory la directory del classifier, collega:

- password → `stdin` del processo;
- JSON → `stdout` del processo;
- diagnostica Python/PyInstaller → `stderr` del processo.

### 17.2 Protocollo del processo

Input:

- byte grezzi su stdin;
- nessun argomento da riga di comando;
- limite Python corrente di 256 byte.

Output:

```json
{
  "version": 1,
  "classe": "Debole",
  "classe_id": 0,
  "probabilita": {
    "debole": 1.0,
    "media": 0.0,
    "forte": 0.0
  }
}
```

Go valida:

- versione del protocollo;
- corrispondenza tra `classe_id` e nome classe;
- probabilità finite e comprese tra 0 e 1.

Non verifica ancora esplicitamente che la somma delle probabilità sia circa 1.

### 17.3 Architettura della rete

La rete corrente usa:

- vocabolario di 96 simboli: padding, unknown, lettere ASCII, cifre e punteggiatura;
- embedding di dimensione 16;
- prima convoluzione 1D da 16 a 32 canali, kernel 3 e padding 1;
- dropout 0,2;
- seconda convoluzione 1D da 32 a 32 canali, kernel 3;
- masked max pooling temporale;
- concatenazione di due feature manuali: lunghezza normalizzata ed entropia empirica dei caratteri;
- classificatore lineare da 34 feature a tre classi;
- softmax per le probabilità finali.

Il modello viene ricostruito in `predict.py`, poi vengono caricati i pesi `best_cnn_model.pt`. L'inferenza è eseguita su CPU.

### 17.4 PyInstaller

Il classifier è distribuito in modalità `onedir`, non come singolo file autosufficiente. L'eseguibile principale dipende dalla directory `_internal`, che contiene runtime Python, PyTorch, librerie native e modello. Spostare solo `password-classifier` causa l'errore “Failed to load Python shared library .../_internal/Python”.

Il bundle corrente è specifico della piattaforma e architettura su cui è stato creato. Inoltre include dipendenze non necessarie, come parti di `pyarrow`, perché è stato costruito da un ambiente Python ampio. Prima della distribuzione serviranno ambiente di build minimale, esclusioni PyInstaller e build separate per ogni sistema operativo/architettura.

## 18. Persistenza lato client

Il client usa bbolt nel file:

```text
<ProjectRoot>/database.db
```

Schema logico:

```text
servers/
└── <ServerID 32B>/
    ├── identity                 identità pubblica MessagePack
    ├── endpoint                 host:port
    ├── observed-ip              IP se l'host è un IP
    ├── login-bundle             BundleID 32B
    ├── pass-tokens/
    │   ├── 0x01                 token protobuf
    │   ├── 0x02                 token protobuf
    │   └── 0x03                 token protobuf
    ├── nickname-catalog/
    │   └── Nickname-catalog     JSON
    └── users/
        ├── <nickname>           UserBundle protobuf
        └── auth:<nickname>      0 oppure 1

server:blacklist/
└── <ServerID 32B>               motivo, endpoint e timestamp

private:bundles/
└── <BundleID 32B>/
    ├── private-bundle           MessagePack
    ├── commitment:rawbytes      protobuf privato
    ├── curve-sets/              set privati indicizzati
    └── kem-sets/                set privati indicizzati
```

Le identity key cifrate sono inoltre salvate nel filesystem sotto `data/bundle_<ID>_IK_keys/`.

## 19. Persistenza lato server

Il server usa due database Badger distinti.

### 19.1 Database principale

Percorso:

```text
<storage.BasePath>/database
```

Contiene:

- versione schema corrente 2;
- identità server cifrata/persistita;
- `BundleID → PublicBundle`;
- `nickname:<name> → BundleID`;
- `reserved:<name> → prenotazione con TTL di cinque minuti`;
- prekey curve indicizzate per BundleID;
- prekey KEM indicizzate per BundleID.

Il salvataggio di nickname, bundle e prekey avviene in una singola transazione, dopo tutte le validazioni costose.

Limiti correnti:

- massimo 1000 set per tipo;
- public bundle massimo 64 KiB;
- curve set massimo 8 KiB;
- KEM set massimo 10 KiB;
- nickname 5–15 caratteri ASCII ammessi.

### 19.2 Database token

Percorso:

```text
<storage.BasePath>/token_db
```

Contiene:

- versione schema corrente 1;
- chiave privata blind di registrazione cifrata;
- hash dei token già usati per deduplicazione.

La verifica “controlla e salva se nuovo” è protetta da mutex e transazione. I record di deduplicazione dei pass token correnti non hanno TTL, quindi restano persistenti anche dopo la scadenza della relativa chiave: è un punto da migliorare con pulizia per epoca o TTL.

## 20. Autenticazione e presenza sul server

Ogni `Connection` può contenere un `AuthenticatedUser`.

Login completo:

- memorizza il BundleID;
- segna `PoWVerified`;
- aggiunge la connessione alla mappa globale `activeUsers[BundleID]`.

Login rapido:

- crea un utente autenticato anonimo;
- non inserisce un BundleID nella mappa di presenza.

La presenza è solo in RAM. Alla chiusura della connessione viene rimossa. `ActiveConnections` conta le connessioni associate a un BundleID, ma oggi non applica un limite. `LastSeen` viene aggiornato quando inizia la gestione di una fase, non a ogni singolo pacchetto.

## 21. HSM e protezione delle chiavi persistenti

Il progetto contiene due backend:

- macOS: Secure Enclave P-256 ECIES tramite Security.framework e CGo;
- Linux/Windows: TPM 2.0 con blob sigillati e combinazione HMAC + AES-256.

Senza HSM, le chiavi private sono protette tramite Argon2id e AES-256-GCM. Nel flusso CLI corrente registrazione server e client passano `useHSM = false`; quindi il supporto esiste ma non viene selezionato dall'interfaccia principale.

Su macOS un binario che usa davvero la Secure Enclave deve essere inserito in un bundle `.app`, corredato del provisioning profile e firmato con gli entitlement corretti. Un semplice `go run` non basta per quel percorso.

## 22. Logging

`p2log` apre:

```text
<storage.BasePath>/Log Files/log_console.log
```

Comportamento corrente:

| Livello | File | stdout | stderr |
|---|---:|---:|---:|
| Debug | sì | no | no |
| Info | sì | no | no |
| Warning | sì | sì | no |
| Error | sì | sì | sì |

Perciò un errore è duplicato sulle due console standard. Il file contiene oggetti JSON uno per riga, ma ogni apertura aggiunge anche righe di intestazione testuali: non è quindi un documento JSON unico rigoroso e non è nemmeno NDJSON puro.

Per seguire il file in una seconda finestra:

```bash
tail -f "data/Log Files/log_console.log"
```

Non serve `2>` per portare nel file i messaggi gestiti da `p2log`, perché il logger li salva direttamente. La redirezione `2>` riguarda soltanto lo stream stderr del processo e può essere utile per errori prodotti da librerie esterne o runtime che non passano da `p2log`.

## 23. Frontend Tauri

`P2Chat-UI` usa:

- Tauri v2;
- React 19;
- TypeScript;
- Vite;
- Tailwind 4.

Sono presenti schermate per dashboard, setup, chat, sicurezza e log. Al momento però `src-tauri/src/lib.rs` crea soltanto il builder Tauri e non registra comandi che chiamino il backend Go. I dati visualizzati sono in gran parte mock/statici.

Di conseguenza oggi esistono due prodotti separati:

- backend/protocollo funzionante come CLI Go;
- prototipo UI visuale.

Serve ancora definire il confine di processo e l'API tra i due. Possibili opzioni future sono sidecar Go controllato da Tauri, libreria C ABI oppure API locale strettamente autenticata. La soluzione più coerente con l'eseguibile Go attuale è probabilmente un sidecar con protocollo IPC strutturato, ma non è ancora implementata.

## 24. Cosa passa e cosa non passa sulla rete

| Dato | Resta client | Va al server |
|---|---:|---:|
| Password bundle | sì | no |
| Risultato CNN | sì | no |
| Chiavi private utente | sì | no |
| Segreto commitment | sì | no |
| Identity key pubbliche | no | sì |
| Commitment pubblico e firme | no | sì |
| Public bundle e public prekey | no | sì |
| Prova firmata di login | no | sì |
| Token ciechi | copia locale | sì al momento dell'uso |
| TLS exporter binding | memoria della connessione | usato da entrambi, non persistito |

Il server non può e non deve controllare se la password utente ha 16 byte o se la CNN l'ha classificata come forte. Quella è una policy locale applicata prima di generare e cifrare il bundle.

## 25. Stato dei test e modalità di verifica

Durante l'integrazione più recente sono stati verificati con successo:

- test del package `cnn_password`, incluso l'avvio reale del classifier;
- test mirati del commitment a 16/15 byte;
- compilazione del package `cmd/client` tramite `go test -run '^$'`.

Questo non equivale a dire che l'intero repository, tutte le build tag e tutti i test hardware passino nel working tree corrente.

Comandi consigliati:

```bash
go test ./cmd/client/internals/...
go test ./cmd/client/database/...
go test ./cmd/server/...
go build ./cmd/client
go build ./cmd/server
```

Per il frontend:

```bash
cd P2Chat-UI
npm run build
```

I test Secure Enclave richiedono firma e provisioning; i test TPM devono saltare correttamente quando l'hardware non è disponibile.

## 26. Limiti e debito tecnico corrente

### 26.1 Funzionalità mancanti

- protocollo completo di chat tra utenti;
- derivazione e gestione delle sessioni E2E dopo il download dei bundle;
- consumo atomico e rotazione delle one-time prekey;
- gestione contatti completa;
- riconnessione automatica;
- bridge Tauri/Go;
- packaging/installazione multipiattaforma;
- UX completa per cambio password, recupero e migrazione identità.

### 26.2 Limiti di protocollo o implementazione

- Il login rapido autentica anonimamente e non lega la sessione a un BundleID.
- I token usati rimangono nel DB di deduplicazione senza TTL.
- L'identificazione applicativa avviene dopo TCP/TLS: non impedisce flooding pre-identificazione.
- `ActiveConnections` conta ma non limita le connessioni per utente.
- La protezione da traffic analysis è solo parziale.
- Il client accetta password Unicode contando byte, mentre il modello mappa i caratteri non presenti nel vocabolario a `UNK`.
- Il classifier PyInstaller espone temporaneamente la password alla memoria di un processo Python non `mlock`.
- Il path del classifier dipende da `storage.ProjectRoot`, individuato cercando `go.mod`: non è ancora adatto a un'app installata fuori dal repository.
- Il bundle PyInstaller corrente è molto grande e contiene dipendenze inutili.
- I limiti delle fasi catalogo/bundle ammettono payload di vari MiB, ma il framing di trasmissione rifiuta messaggi oltre 64 KiB. I limiti devono essere resi coerenti o va introdotto il chunking.
- Il logger mescola intestazioni testuali e righe JSON nello stesso file.
- `readCommitmentSecret` restituisce errore sotto 16 byte invece di ripetere il prompt, a differenza della password bundle.

### 26.3 Pulizia del repository

Nel working tree sono presenti database, log, directory Tor, chiavi di prova, build Python, dataset e artefatti generati. Prima di distribuire o pubblicare il progetto occorre:

- definire con precisione `.gitignore`;
- rimuovere dal versionamento segreti e stato runtime;
- separare sorgenti da artefatti di build;
- decidere come distribuire il classifier per piattaforma;
- evitare che dataset e bundle pesanti entrino accidentalmente nel prodotto finale.

## 27. Priorità consigliate

Ordine tecnico suggerito per proseguire:

1. stabilizzare il working tree e far passare test completi client/server;
2. correggere incongruenze dei limiti di frame e payload;
3. rendere il packaging del classifier riproducibile e multipiattaforma;
4. definire il protocollo di consumo atomico delle prekey;
5. implementare la creazione della sessione E2E tra due utenti;
6. implementare invio, ricezione e persistenza dei messaggi;
7. aggiungere riconnessione e ripristino di stato;
8. progettare e implementare il bridge Tauri ↔ Go;
9. completare hardening, rate limit, fuzzing e test di integrazione;
10. preparare packaging, migrazioni DB e distribuzione.

## 28. Invarianti da ricordare durante le prossime modifiche

- La password non deve mai essere inviata al server.
- Le chiavi private non devono entrare nello stato delle fasi di rete.
- `Connection.Login()` deve restare senza argomenti.
- L'orchestratore risponde agli `Events` con `PutRouter`.
- `PutOutgoing` è riservato a messaggi già destinati alla rete.
- Ogni attesa di fase deve avere un timeout.
- Ogni nuova fase server deve essere registrata e importata.
- Ogni payload deve avere validazione di tag e dimensione prima del parsing costoso.
- I segreti devono usare `memguard` e devono essere distrutti appena possibile.
- Non si deve azzerare direttamente `buffer.Bytes()` se quel buffer deve restare valido.
- Le firme ML-DSA e XEdDSA vanno entrambe verificate nei punti in cui il protocollo richiede identità ibrida.
- I BundleID, ServerID, nonce, hash e binding da 32 byte non sono password e non devono essere ridotti quando cambia la policy della password.
- La CNN è una policy locale di registrazione, non un elemento di autenticazione del protocollo.

## 29. Definizione pratica di “fin dove siamo arrivati”

Oggi P2Chat è in grado di:

1. avviare un server persistente con identità crittografica;
2. connettere un client attraverso Tor e TLS ibrido;
3. identificare e pinning il server a livello applicativo;
4. creare una nuova identità utente con password non classificata come debole;
5. ottenere anonimamente un token dopo aver pagato un costo PoW;
6. creare localmente bundle e prekey PQXDH;
7. registrare nickname e bundle sul server con doppia prova di possesso;
8. effettuare un login completo con identità e PoW;
9. ricevere e usare tre credenziali anonime per login rapidi successivi;
10. richiedere un catalogo nickname autenticato;
11. scaricare un bundle mescolando il target con due decoy;
12. verificare fuori banda il commitment del proprietario;
13. salvare localmente il bundle ricevuto.

Il passo architetturale successivo non è aggiungere altre schermate o altre fasi isolate: è collegare questi mattoni al protocollo di instaurazione della sessione tra utenti e, sopra di esso, al trasporto dei messaggi cifrati. Solo dopo quel collegamento la UI potrà pilotare un flusso chat realmente end-to-end.
