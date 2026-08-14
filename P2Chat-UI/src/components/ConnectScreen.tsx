import { useEffect, useRef, useState } from "react";
import type { ConnState } from "../App";

interface StackLayer {
  id: string;
  name: string;
  detail: string;
  step: "pending" | "active" | "done";
  log: string;
}

const LAYERS: Omit<StackLayer, "step">[] = [
  { id: "tor", name: "Tor", detail: "InitializeTor → DialTor → EstablishTor (SOCKS5)", log: "tor bootstrapped, circuit established" },
  { id: "tls", name: "TLS 1.3", detail: "CurvePreferences: X25519MLKEM768 + X25519", log: "TLS handshake complete, PQ key exchange negotiated" },
  { id: "yamux", name: "Yamux", detail: "Multiplexed streams, ConnectionManager (GlobalOut, Done)", log: "yamux client session open" },
  { id: "session", name: "SingleSession", detail: "38B header · tag 1B · padding 250-750B · SHA-256", log: "session stream ready, listener + writer up" },
];

export default function ConnectScreen({
  conn,
  setConn,
}: {
  conn: ConnState;
  setConn: (c: ConnState) => void;
}) {
  const [layers, setLayers] = useState<StackLayer[]>(LAYERS.map((l) => ({ ...l, step: "pending" })));
  const [address, setAddress] = useState("151.48.81.210");
  const [port, setPort] = useState("9000");
  const [log, setLog] = useState<string[]>(["p2log · watchdog armed (SIGINT/TERM/SEGV/BUS → memguard.Purge)"]);
  const timer = useRef<number | null>(null);

  useEffect(() => () => {
    if (timer.current) window.clearInterval(timer.current);
  }, []);

  const pushLog = (line: string) => setLog((l) => [...l.slice(-40), line]);

  const connect = () => {
    if (conn !== "offline") return;
    setConn("connecting");
    setLayers(LAYERS.map((l) => ({ ...l, step: "pending" })));
    setLog([]);
    pushLog("p2log · watchdog armed (SIGINT/TERM/SEGV/BUS → memguard.Purge)");

    let i = 0;
    timer.current = window.setInterval(() => {
      setLayers((prev) =>
        prev.map((l, idx) => {
          if (idx < i) return { ...l, step: "done" };
          if (idx === i) return { ...l, step: "active" };
          return { ...l, step: "pending" };
        }),
      );
      if (i > 0) pushLog(`info · ${LAYERS[i - 1].name}: ${LAYERS[i - 1].log}`);
      i += 1;
      if (i > LAYERS.length) {
        if (timer.current) window.clearInterval(timer.current);
        pushLog("info · connection established — waiting for registration phase");
        setLayers((prev) => prev.map((l) => ({ ...l, step: "done" })));
        setConn("online");
      }
    }, 1100);
  };

  return (
    <div className="mx-auto flex min-h-full max-w-6xl flex-col gap-6 px-10 py-10">
      <header className="step-in">
        <h1 className="text-2xl font-semibold tracking-tight">Connect to server</h1>
        <p className="mt-1 text-sm text-muted">
          Bootstrap composes Tor → TLS 1.3 → yamux into a single <code className="font-mono text-cyan-glow/90">InitializeServerConn</code> call.
        </p>
      </header>

      <div className="step-in grid grid-cols-[340px_1fr] gap-6" style={{ animationDelay: "60ms" }}>
        <div className="glass rounded-2xl p-5">
          <label className="text-[11px] font-medium uppercase tracking-wider text-muted">Server</label>
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            className="mt-1 w-full rounded-lg border border-edge bg-ink px-3 py-2 font-mono text-sm text-fg outline-none focus:border-cyan-glow/50"
            spellCheck={false}
          />
          <label className="mt-4 block text-[11px] font-medium uppercase tracking-wider text-muted">Port</label>
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            className="mt-1 w-full rounded-lg border border-edge bg-ink px-3 py-2 font-mono text-sm text-fg outline-none focus:border-cyan-glow/50"
            spellCheck={false}
          />

          <button
            onClick={connect}
            disabled={conn !== "offline"}
            className={`mt-5 w-full rounded-xl py-2.5 text-sm font-semibold transition-all ${
              conn === "online"
                ? "cursor-default bg-emerald-500/15 text-emerald-300"
                : conn === "connecting"
                  ? "cursor-wait bg-edge/70 text-muted"
                  : "bg-gradient-to-r from-cyan-500/20 to-violet-500/20 text-fg hover:from-cyan-500/30 hover:to-violet-500/30 glow-ring"
            }`}
          >
            {conn === "online" ? "Connected" : conn === "connecting" ? "Establishing…" : "Connect"}
          </button>

          <div className="mt-5 rounded-xl border border-edge bg-panel-2 p-3">
            <div className="text-[10px] font-medium uppercase tracking-wider text-muted">Runtime log</div>
            <div className="mt-2 max-h-40 space-y-1 overflow-y-auto font-mono text-[10px] leading-snug text-muted">
              {log.map((l, i) => (
                <div key={i}>{l}</div>
              ))}
            </div>
          </div>
        </div>

        <div className="flex flex-col justify-center gap-3">
          {layers.map((l, i) => (
            <div
              key={l.id}
              className={`glass flex items-center gap-4 rounded-2xl px-5 py-4 transition-all duration-300 ${
                l.step === "active" ? "glow-ring border-cyan-glow/40" : ""
              } ${l.step === "done" ? "opacity-90" : l.step === "pending" ? "opacity-50" : ""}`}
            >
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full border font-mono text-[10px] ${
                  l.step === "done"
                    ? "border-emerald-400/40 bg-emerald-400/10 text-emerald-300"
                    : l.step === "active"
                      ? "border-cyan-glow/50 bg-cyan-glow/10 text-cyan-glow"
                      : "border-edge text-muted"
                }`}
              >
                {l.step === "done" ? "✓" : l.step === "active" ? i + 1 : i + 1}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-semibold">{l.name}</span>
                  {l.step === "active" && <span className="h-1.5 w-1.5 rounded-full bg-cyan-glow pulse-dot" />}
                </div>
                <div className="truncate font-mono text-[11px] text-muted">{l.detail}</div>
              </div>
              {l.step === "done" && <span className="font-mono text-[10px] text-emerald-400/80">ok</span>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
