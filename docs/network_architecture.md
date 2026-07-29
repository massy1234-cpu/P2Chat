# Network Architecture (current state)

## Struct hierarchy

```
┌──────────────────────────────────────────────────────┐
│                    ConnectionManager                  │
│  ┌─────────────────────────────────────────────────┐  │
│  │  Conn: *Connection                              │  │
│  │  Tor: *tor.Tor                                  │  │
│  │  GlobalOut: chan<- []byte  ◄── UNICA reference   │  │
│  │  Done: chan struct{}                             │  │
│  └─────┬───────────────────────────────────────────┘  │
│        │                                              │
│  ┌─────▼───────────────────────────────────────────┐  │
│  │                  Connection                      │  │
│  │  MasterSession: *yamux.Session                   │  │
│  │  ActiveSessions: sync.Map  [ID → *SingleSession] │  │
│  │  GlobalOut: chan<- []byte ─── same reference ────┼──┤
│  │  Done: chan struct{}                             │  │
│  │  nextID, freeIDs, mu                             │  │
│  └─────┬───────────────────────────────────────────┘  │
│        │                                              │
│  ┌─────▼───────────────────────────────────────────┐  │
│  │               SingleSession x N                   │  │
│  │  ID: uint32                                      │  │
│  │  Tag: string                                     │  │
│  │  Stream: *yamux.Stream                           │  │
│  │  Incoming: chan []byte                           │  │
│  │  Outgoing: chan []byte                           │  │
│  │  GlobalOut: chan<- []byte ─── same reference ────┼──┤
│  │  Done: chan struct{}                             │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

**GlobalOut** è unica (`make(chan []byte)` in `Wrapper()`), passata per reference a `Connection` e a ogni `SingleSession` via `NewSession`.

## Thread-safety principles

The logic behind the methods in the structs is that every method should only call `Close()` and then the function will do all the work, because the `Close()` function is thread-safe. In this way all the structs can end cleanly without errors.

---

## Data flow

```
                          ┌──────────────┐
                          │     Wire     │
                          └──────┬───────┘
                                 │
                    ┌────────────▼────────────┐
                    │   yamux.MasterSession    │
                    └────────────┬────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             │  AcceptStream()   │   OpenStream()    │
             ▼                   ▼                   ▼
     ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
     │ SingleSession  │  │ SingleSession  │  │ SingleSession  │
     │ (server->cli)  │  │  (client->sv)  │  │    (P2P)      │
     └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
             │                  │                  │
     ┌───────▼───────┐  ┌───────▼───────┐  ┌───────▼───────┐
     │   Listener()  │  │   Listener()  │  │   Listener()  │
     │               │  │               │  │               │
     │ ReadMessage() │  │ ReadMessage() │  │ ReadMessage() │
     │     → err     │  │     → err     │  │     → err     │
     │ return        │  │ return        │  │ return        │
     └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
             │                  │                  │
             ▼                  ▼                  ▼
      session.Incoming ◄─── chan []byte ◄─── session.Incoming
             │
             ▼
     [Dispatch / ReaderManager — TODO]
```

### Read path

```
yamux.Stream ──► transmission.ReadMsg ──► session.Incoming ──► ??? (Dispatch)
```

### Write path

```
??? (handler/upper layer) ──► session.Outgoing ──► session.Writer()
                                                         │
                                                   transmission.WriteMsg
                                                         │
                                                   yamux.Stream ──► Wire
```

### Global path

```
SingleSession / Connection ──► select { GlobalOut <- msg; case <-Done }
                                        │
                                   ConnectionManager.GlobalOut
                                        │
                                   ??? (consumer upper layer — TODO)
```

---

## Session lifecycle

```
Client opens stream
        │
        ▼
    yamux.Session.OpenStream()
        │
        ▼
    NewSession(ID, stream, globalOut)
        │
        ├── make(chan []byte) per Incoming, Outgoing
        ├── make(chan struct{}) per Done
        ├── go session.Listener()    ── loop: ReadMessage → Incoming
        └── go session.Writer()      ── select: Outgoing → WriteMessage | Done → return
        │
        ▼
    session attiva, registrata in Connection.ActiveSessions

        ...
        │
        ▼
    session.Close()
        │
        └── close(session.Done)
                │
                ├── Writer: <-Done → return
                └── Listener: ReadMessage fallisce (stream chiuso da remoto) → return
```

---

## Server-side incoming sessions

```
Connection.ListenOnWire()
        │
        ├── go func() { <-c.Done → c.MasterSession.Close() }
        │
        └── loop:
                │
                ├── c.MasterSession.AcceptStream()  ← bloccante
                │       │
                │       ▼
                │   NewSession(ID, stream, c.GlobalOut)
                │       │
                │       ▼
                │   c.ActiveSessions.Store(ID, sess)
                │
                └── error → return
```

---

## Close chain (current, with issues)

```
ConnectionManager.Close()
        │
        ├── manager.Conn.Close()
        │       │
        │       ├── Range ActiveSessions → ReleaseSession each
        │       │       │
        │       │       ├── ReleaseID(session.ID)
        │       │       ├── session.Close()
        │       │       │       └── close(session.Done)
        │       │       └── ActiveSessions.Delete(session.ID)
        │       │
        │       └── c.MasterSession.Close()
        │
        ├── manager.Tor.Close()             ── panico se Tor == nil
        ├── close(manager.GlobalOut)        ── (1)
        └── close(manager.Done)             ── (2) ── ordine invertito
```

---

## Known issues

| Issue | Dove | Effetto |
|-------|------|---------|
| `c.Done` mai chiuso | `Connection.Close()` | Goroutine leak sentinella in `ListenOnWire` |
| Doppia `Stream.Close()` | `SingleSession.Close()` + sentinella `Listener()` | Idempotente ma sporco |
| `Tor.Close()` su nil | `ConnectionManager.Close()` | Panico se Tor non inizializzato |
| `close(GlobalOut)` prima di `close(Done)` | `ConnectionManager.Close()` | Potenziale panic su send a canale chiuso |
| `NewSession` possibile nil | `ListenOnWire()` | Store di nil nella map |
| ReadManager / WriterManager | `manager/*.go` | Solo stub vuoti |
| Consumatore `GlobalOut` | — | Nessuno ancora |
| Riconnessione | — | Non implementata |
