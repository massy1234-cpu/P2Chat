import { useState } from "react";
import { CRYPTO_KEYS, HSM_OPTIONS } from "../data/security";
import { Card, IconChip, IconLock, IconRow, IconShield } from "./ui";

export default function SecurityScreen() {
  const [hsm, setHsm] = useState("se");
  const [argonLevel, setArgonLevel] = useState(2);

  return (
    <div className="mx-auto max-w-6xl px-10 py-10">
      <header className="step-in">
        <h1 className="text-[26px] font-bold tracking-tight text-text-primary">Your Security</h1>
        <p className="mt-1 text-sm text-text-secondary">Everything is protected by high-standard decentralized security protocols</p>
      </header>

      <div className="step-in mt-8 space-y-3" style={{ animationDelay: "60ms" }}>
        <IconRow icon={<IconShield className="h-5 w-5" />} title="Your messages are encrypted" description="End-to-end local cryptosystems ensure only you and your peer hold valid readable decryption signatures." />
        <IconRow icon={<IconLock className="h-5 w-5" />} title="Your keys are stored securely" description="Private signing assets remain heavily isolated inside sandbox device memory structures." />
        <IconRow icon={<IconChip className="h-5 w-5" />} title="Hardware protection: active" description="Local hardware keystore and cryptoprocessor chips handle key protection validation protocols." />
      </div>

      <div className="step-in mt-8 grid grid-cols-2 gap-6" style={{ animationDelay: "120ms" }}>
        <Card>
          <div className="text-sm font-semibold text-text-primary">Hardware Security Module</div>
          <div className="mt-3 flex flex-col gap-2">
            {HSM_OPTIONS.map((h) => (
              <button
                key={h.id}
                onClick={() => setHsm(h.id)}
                className={`rounded-xl border px-4 py-3 text-left transition-all duration-200 hover:-translate-y-0.5 ${
                  hsm === h.id
                    ? "border-primary bg-primary-50 shadow-[0_4px_12px_rgba(47,111,237,0.15)]"
                    : "border-border bg-white hover:bg-black/5"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-text-primary">{h.name}</span>
                  <span
                    className={`flex h-5 w-5 items-center justify-center rounded-full transition-all ${
                      hsm === h.id ? "bg-primary text-white" : "border-2 border-edge-2"
                    }`}
                  >
                    {hsm === h.id && (
                      <svg viewBox="0 0 24 24" className="h-3 w-3" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                    )}
                  </span>
                </div>
                <div className="mt-0.5 text-xs text-text-secondary">{h.platform}</div>
              </button>
            ))}
          </div>
        </Card>

        <Card>
          <div className="text-sm font-semibold text-text-primary">Key Derivation · Argon2id</div>
          <div className="mt-3 flex gap-2">
            {[1, 2, 3].map((lv) => (
              <button
                key={lv}
                onClick={() => setArgonLevel(lv)}
                className={`relative flex-1 rounded-xl border px-3 py-3 text-center transition-all duration-200 hover:-translate-y-0.5 ${
                  argonLevel === lv
                    ? "border-primary bg-primary-50 shadow-[0_4px_12px_rgba(47,111,237,0.15)]"
                    : "border-border bg-white hover:bg-black/5"
                }`}
              >
                {argonLevel === lv && (
                  <span className="absolute right-2 top-2 flex h-4 w-4 items-center justify-center rounded-full bg-primary text-white">
                    <svg viewBox="0 0 24 24" className="h-2.5 w-2.5" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 6L9 17l-5-5" />
                    </svg>
                  </span>
                )}
                <div className="text-sm font-semibold text-text-primary">Level {lv}</div>
                <div className="mt-1 text-xs text-text-secondary">{lv === 1 ? "low · fast" : lv === 2 ? "medium" : "high · slow"}</div>
              </button>
            ))}
          </div>
          <div className="mt-4 rounded-xl border border-border bg-slate-50 p-3 text-xs leading-relaxed text-text-secondary">
            <div>salt · AES-256-GCM · commitment scheme</div>
            <div>watchdog → memguard.Purge on crash</div>
            <div>storage: SK.bin (encrypted) · PK.bin · bbolt</div>
          </div>
        </Card>
      </div>

      <div className="step-in mt-8">
        <div className="text-sm font-semibold text-text-primary">Post-quantum keys</div>
        <div className="mt-3 grid grid-cols-2 gap-3">
          {CRYPTO_KEYS.map((k) => (
            <Card key={k.name} className="flex items-center justify-between">
              <div>
                <div className="font-mono text-sm font-semibold text-primary">{k.name}</div>
                <div className="mt-0.5 text-xs text-text-secondary">{k.role}</div>
                <div className="mt-1 font-mono text-[10px] text-text-muted">{k.size}</div>
              </div>
              <div className="rounded border border-border px-2 py-0.5 font-mono text-[10px] text-text-muted">{k.standard}</div>
            </Card>
          ))}
        </div>
      </div>

      <div className="step-in mt-8 flex items-center gap-4 rounded-[20px] bg-success-50 px-6 py-5">
        <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-success text-white">
          <IconShield className="h-5 w-5" />
        </div>
        <div>
          <div className="text-sm font-semibold text-success-dark">All good — your account is fully protected</div>
          <div className="mt-0.5 text-xs text-success-dark/80">Zero vulnerabilities detected. Device signatures are healthy and fully encrypted.</div>
        </div>
      </div>
    </div>
  );
}