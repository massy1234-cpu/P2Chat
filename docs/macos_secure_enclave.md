## 6. Il sistema di firma di Apple — tre livelli sovrapposti

Questa è la parte che ha richiesto più lavoro. Apple ha costruito tre livelli di sicurezza sovrapposti che devono essere tutti soddisfatti simultaneamente.

### Livello 1 — Il certificato Developer

Per usare le API Security avanzate (Secure Enclave, Keychain permanente), il binario deve essere firmato con un certificato Apple Developer valido. Un binario non firmato o firmato ad-hoc (`codesign -s -`) viene bloccato da AMFI.

Il certificato si ottiene con Xcode → Settings → Accounts → aggiungere Apple ID → Manage Certificates → Apple Development.

**Il certificato ha questa struttura interna:**
```
CN = Apple Development: massimogonnella06@gmail.com (H6SMX58D5C)
OU = Y635V7TUJU
O  = Massimo Gonnella
C  = US
```

**Scoperta critica**: `H6SMX58D5C` appare nel `CN` del certificato e viene mostrato da `security find-identity -v -p codesigning` tra parentesi, facendo sembrare che sia il Team ID. **Non è il Team ID.** Il vero Team ID che macOS usa per il provisioning e il keychain è `Y635V7TUJU`, nel campo `OU` (Organizational Unit) del certificato.

Questo è stato scoperto con:
```bash
security find-certificate -a -c "Apple Development" -p | openssl x509 -noout -subject
# output: subject=UID=993XV6JRU8, CN=Apple Development: ...@gmail.com (H6SMX58D5C), OU=Y635V7TUJU, ...
```

Aver messo inizialmente `H6SMX58D5C` negli entitlement invece di `Y635V7TUJU` ha causato svariati errori di firma.

**Problema del certificato intermedio (WWDR):**
Il primo tentativo di firma ha dato:
```
Warning: unable to build chain to self-signed root for signer "Apple Development: ..."
macos.test: errSecInternalComponent
```
Causa: il certificato intermedio Apple (WWDR — Worldwide Developer Relations) non era installato nel keychain locale. Senza di esso, `codesign` non riesce a costruire la catena di fiducia dal certificato Developer fino alla root CA di Apple.
Soluzione: Xcode → Settings → Accounts → Manage Certificates → ricrea il certificato. Xcode scarica automaticamente il WWDR mancante.

### Livello 2 — Gli entitlement

Gli entitlement sono dichiarazioni che il binario fa a macOS: "ho bisogno di questi permessi specifici". Vengono incorporati crittograficamente nella firma digitale. Se dichiari un entitlement che non ti è stato concesso, AMFI uccide il processo immediatamente con SIGKILL (exit code 137) — il processo non esegue nemmeno una riga di codice.

Il file `entitlements_storage.plist` contiene:

```xml
<key>com.apple.security.app-sandbox</key>
<false/>
```
Tool CLI e binari di test non sono app sandboxed. Impostare questo a `false` è necessario altrimenti il processo non può fare niente.

```xml
<key>com.apple.application-identifier</key>
<string>Y635V7TUJU.com.p2chat</string>
```
Identifica l'applicazione al keychain di sistema. Il formato è `TEAM_ID.bundle_identifier`. Senza questo, le operazioni sul keychain non sanno a quale "spazio" appartengono le chiavi.

```xml
<key>com.apple.developer.team-identifier</key>
<string>Y635V7TUJU</string>
```
Conferma il Team ID. Deve corrispondere al `OU` del certificato di firma.

```xml
<key>keychain-access-groups</key>
<array>
    <string>Y635V7TUJU.*</string>
</array>
```
Autorizza l'app ad accedere al keychain e al Secure Enclave per operazioni permanenti. Il `.*` è un wildcard che permette l'accesso a qualsiasi access group del team. **Questo è un entitlement ristretto** — da solo non basta, serve il Livello 3.

### Livello 3 — Il provisioning profile

`keychain-access-groups` è classificato da Apple come entitlement ristretto. macOS non accetta che tu lo dichiari semplicemente negli entitlement — richiede una **garanzia firmata da Apple** che tu sia autorizzato. Questa garanzia è il provisioning profile.

Un provisioning profile è un file XML firmato con la chiave privata di Apple che certifica la seguente relazione:

```
Bundle ID: com.p2chat
Team ID: Y635V7TUJU
Certificati autorizzati: [lista certificati]
Entitlement concessi: keychain-access-groups: Y635V7TUJU.*
Dispositivi autorizzati: [UUID del Mac]
Scadenza: 7 giorni (per profile locali gratuiti)
```

AMFI (Apple Mobile File Integrity) è un daemon del kernel che, prima di eseguire qualsiasi processo con entitlement ristretti, verifica che esista un provisioning profile valido che autorizzi quella combinazione di certificato + entitlement. Se non lo trova: SIGKILL.

**Come è stato creato il provisioning profile gratuitamente:**
Il portale developer.apple.com richiede un account a pagamento ($99/anno) per registrare App ID. Xcode però può creare provisioning profile locali gratuitamente:

1. Xcode → File → New → Project → macOS App
2. Bundle Identifier: `com.p2chat`, Team: account Apple
3. Signing & Capabilities → `+` Capability → Keychain Sharing → aggiunto `com.p2chat`
4. Build (⌘B) → Xcode registra automaticamente l'App ID sul portale e scarica il profile

Il profile viene salvato in:
```
~/Library/Developer/Xcode/UserData/Provisioning Profiles/
```

Il profile ha una scadenza di **7 giorni** per gli account gratuiti. Dopo 7 giorni va rigenerato da Xcode con un nuovo build.

**Perché `codesign --provisioning-profile` non funziona:**
Il flag `--provisioning-profile` non esiste in `codesign` per binari standalone. Il provisioning profile può essere incorporato solo in un **app bundle** (struttura di directory `.app`), non in un singolo eseguibile. Soluzione: creare un mini bundle intorno al binario di test.

**Struttura del bundle creato:**
```
macos_test.app/
  Contents/
    Info.plist                  ← descrive il bundle (bundle ID, executable name)
    MacOS/
      macos.test                ← il binario Go compilato
    embedded.provisionprofile   ← il profile firmato da Apple
```

`Info.plist` minimo necessario:
```xml
<key>CFBundleIdentifier</key>
<string>com.p2chat</string>
<key>CFBundleExecutable</key>
<string>macos.test</string>
```

Il bundle ID in `Info.plist` deve corrispondere esattamente a quello nel provisioning profile, altrimenti AMFI rifiuta.

---

## 7. L'ACL e l'errore `-25293 errSecAuthFailed`

Anche con certificato valido, entitlement corretti e provisioning profile presente, il test falliva:

```
CreateSecret failed, error: error during the creation of secret, error: -25293
```

`-25293` è `errSecAuthFailed` — autenticazione fallita. La causa era il flag `kSecAccessControlPrivateKeyUsage` nell'ACL:

```c
SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    kSecAccessControlPrivateKeyUsage,  // ← questo causava il problema
    err
);
```

`kSecAccessControlPrivateKeyUsage` dice al SE che la chiave può essere usata solo per operazioni crittografiche. Questo ha senso per l'**uso** della chiave. Il problema è che su macOS, questo flag fa sì che anche la **creazione** della chiave richieda autenticazione utente (Touch ID o password del keychain). Un binario di test in un terminale non ha un contesto UI per mostrare il dialog di autenticazione, quindi l'operazione fallisce.

Soluzione: impostare i flag a `0` durante lo sviluppo. Questo crea comunque una chiave SE sicura (protetta da `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), ma senza richiedere autenticazione.

```c
SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    0,    // nessun flag di operazione aggiuntivo
    err
);
```

`kSecAccessControlPrivateKeyUsage` andrà reintrodotto in produzione insieme a `LAContext` (Local Authentication framework) che permette di gestire l'autenticazione Touch ID programmaticamente.

---

## 8. Errore `-34018 errSecMissingEntitlement`

Prima di risolvere il problema del provisioning profile, si è tentato di usare solo gli entitlement senza il profile. L'errore era:

```
error during the creation of secret, error: -34018
```

`-34018` è `errSecMissingEntitlement`. macOS verificava che il processo avesse l'entitlement `keychain-access-groups`, non lo trovava validato da nessun provisioning profile, e rifiutava l'operazione. A differenza di SIGKILL (dove il processo viene ucciso prima di partire), qui il processo parte ma l'operazione specifica viene rifiutata.

---

## 9. Sequenza di build — ordine obbligatorio

Ogni volta che si modifica il codice Go o C, la sequenza deve essere eseguita in questo ordine esatto:

```bash
# 1. Compila il binario di test
go test -c -o macos.test .

# 2. Copia nel bundle (il bundle deve già esistere)
cp macos.test macos_test.app/Contents/MacOS/macos.test

# 3. Firma il bundle con -f (force, sovrascrive firma esistente)
codesign -f -s "945E1AD0FA3F22DB91B66BA52E00293ACC452238" \
  --entitlements entitlements_storage.plist \
  macos_test.app

# 4. Esegui il binario dal dentro il bundle
./macos_test.app/Contents/MacOS/macos.test -test.v
```

**Perché l'ordine è critico**: la firma è un hash crittografico del contenuto del binario. Se modifichi il binario dopo aver firmato, la firma non corrisponde più e AMFI rifiuta l'esecuzione. Per questo va sempre: compila → firma → esegui. Mai modificare dopo aver firmato.

**Cosa significa `-test.v`**: è il flag verbose per i binari di test Go compilati con `go test -c`. Equivale a `go test -v`. Mostra l'output di ogni singola funzione di test con `=== RUN` e `--- PASS/FAIL`.