import { useState } from "react";
import { CRYPTO_KEYS, HSM_OPTIONS } from "../data/security";

export default function SecurityScreen() {
  const [hsm, setHsm] = useState("se");
  const [argonLevel, setArgonLevel] = useState(2);

  const selected = HSM_OPTIONS.find((h) => h.id === hsm)!;

  return (
    <div className="mx-auto max-w-6xl px-10 py-10">
      <header className="step-in">
        <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
        <p className="mt-1 text-sm text-muted">Key material, HSM dispatch and KDF policy — memguard-locked, no swap.</p>
      </header>

      <div className="step-in mt-8 grid grid-cols-2 gap-6" style={{ animationDelay: "60ms" }}>
        <div className="glass rounded-2xl p-5">
          <div className="text-[11px] font-medium uppercase tracking-wider text-muted">HSM module · EncryptHSM</div>
          <div className="mt-3 flex flex-col gap-2">
            {HSM_OPTIONS.map((h) => (
              <button
                key={h.id}
                onClick={() => setHsm(h.id)}
                className={`rounded-xl border px-4 py-3 text-left transition-all ${
                  hsm === h.id ? "border-cyan-glow/40 bg-cyan-glow/5 glow-ring" : "border-edge hover:border-edge-2"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold">{h.name}</span>
                  <span
                    className={`h-2.5 w-2.5 rounded-full border ${hsm === h.id ? "border-cyan-glow bg-cyan-glow" : "border-edge bg-transparent"}`}
                  />
                </div>
                <div className="mt-0.5 font-mono text-[10px] text-muted">{h.platform}</div>
                <div className="mt-1 font-mono text-[10px] text-muted/70">{h.note}</div>
              </button>
            ))}
          </div>
          <div className="mt-4 rounded-xl border border-edge bg-panel-2 p-3 font-mono text-[10px] leading-relaxed text-muted">
            <div>hsm_method: 0=none · 1=SE (darwin) · 2=TPM (linux/windows)</div>
            <div className="text-cyan-glow/80">active: {selected.name} — {selected.note}</div>
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <div className="text-[11px] font-medium uppercase tracking-wider text-muted">KDF · Argon2id (non-HSM)</div>
          <div className="mt-3 flex gap-2">
            {[1, 2, 3].map((lv) => (
              <button
                key={lv}
                onClick={() => setArgonLevel(lv)}
                className={`flex-1 rounded-xl border px-3 py-3 text-center transition-all ${
                  argonLevel === lv ? "border-cyan-glow/40 bg-cyan-glow/5 glow-ring" : "border-edge hover:border-edge-2"
                }`}
              >
                <div className="text-sm font-semibold">Level {lv}</div>
                <div className="mt-1 font-mono text-[10px] text-muted">
                  {lv === 1 ? "low · fast" : lv === 2 ? "medium" : "high · slow"}
                </div>
              </button>
            ))}
          </div>
          <div className="mt-4 space-y-1 rounded-xl border border-edge bg-panel-2 p-3 font-mono text-[10px] leading-relaxed text-muted">
            <div>salt · AES-256-GCM · commitment scheme</div>
            <div>watchdog → memguard.Purge on SIGINT/SIGTERM/SIGSEGV/SIGBUS</div>
            <div>storage: SK.bin (encrypted) · PK.bin (plaintext) · bbolt database.db</div>
          </div>
        </div>
      </div>

      <div className="step-in mt-6" style={{ animationDelay: "120ms" }}>
        <div className="text-[11px] font-medium uppercase tracking-wider text-muted">Key inventory</div>
        <div className="mt-3 grid grid-cols-2 gap-3">
          {CRYPTO_KEYS.map((k) => (
            <div key={k.name} className="glass rounded-2xl p-4">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-semibold text-cyan-glow/90">{k.name}</span>
                <span className="rounded border border-edge px-2 py-0.5 font-mono text-[10px] text-muted">{k.standard}</span>
              </div>
              <div className="mt-1 text-xs text-muted">{k.role}</div>
              <div className="mt-2 font-mono text-[10px] text-muted/70">{k.size}</div>
              <div className="mt-1 font-mono text-[10px] text-muted/70">→ {k.used}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
