import { useEffect, useRef, useState } from "react";
import type { View } from "../App";
import { Button, Card, IconLock, IconShield, IconTerminal } from "./ui";

const STEPS = ["Connect", "Account", "Ready"];

const FEATURES = [
  { icon: <IconShield className="h-4 w-4" />, label: "End-to-end encrypted" },
  { icon: <IconLock className="h-4 w-4" />, label: "Keys never leave your device" },
  { icon: <IconTerminal className="h-4 w-4" />, label: "Anonymous via Tor" },
];

export default function SetupScreen({ onNavigate }: { onNavigate: (v: View) => void }) {
  const [step, setStep] = useState(0);
  const [ready, setReady] = useState(false);
  const [server, setServer] = useState("151.48.81.210");
  const [port, setPort] = useState("9000");
  const timer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timer.current) window.clearTimeout(timer.current);
    },
    [],
  );

  const connect = () => {
    setStep(1);
    setReady(false);
    timer.current = window.setTimeout(() => setReady(true), 3200);
  };

  const pillState = (i: number) => {
    if (i === 0) return step === 0 ? "active" : "done";
    if (i === 1) return step === 0 ? "todo" : ready ? "done" : "active";
    return ready ? "active" : "todo";
  };

  return (
    <div className="flex h-full">
      <div className="hidden w-[400px] shrink-0 flex-col justify-between border-r border-border bg-gradient-to-br from-primary-50 via-white to-success-50 p-10 lg:flex">
        <div>
          <div className="text-[26px] font-bold leading-snug text-text-primary">Private, post-quantum messaging.</div>
          <p className="mt-3 max-w-xs text-sm leading-relaxed text-text-secondary">
            Connect to a signaling server, generate your keys and chat end-to-end. No one in between sees your messages.
          </p>
          <div className="mt-8 space-y-4">
            {FEATURES.map((f) => (
              <div key={f.label} className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-full bg-white text-primary shadow-[0_4px_14px_rgba(15,23,42,0.07)]">
                  {f.icon}
                </div>
                <span className="text-sm text-text-primary">{f.label}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="font-mono text-[11px] text-text-muted">TLS 1.3 · PQXDH · X25519MLKEM768</div>
      </div>

      <div className="flex flex-1 flex-col items-center justify-center px-8">
        <div className="mb-8 flex items-center gap-2">
          {STEPS.map((s, i) => {
            const ps = pillState(i);
            return (
              <div key={s} className="flex items-center gap-2">
                {i > 0 && <div className={`h-px w-8 ${ps === "todo" ? "bg-edge-2" : "bg-primary"}`} />}
                <div
                  className={`flex items-center gap-2 rounded-full px-3 py-1.5 text-xs font-medium ${
                    ps === "todo" ? "border border-border bg-white text-text-muted" : "bg-primary-50 text-primary"
                  }`}
                >
                  <span
                    className={`flex h-5 w-5 items-center justify-center rounded-full text-[10px] font-bold ${
                      ps === "done"
                        ? "bg-primary text-white"
                        : ps === "active"
                          ? "border border-primary text-primary"
                          : "bg-edge-2 text-white"
                    }`}
                  >
                    {ps === "done" ? "✓" : i + 1}
                  </span>
                  {s}
                </div>
              </div>
            );
          })}
        </div>

        {step === 0 && (
          <Card className="w-[420px]">
            <h2 className="text-lg font-bold text-text-primary">Connect to your network</h2>
            <p className="mt-1 text-sm text-text-secondary">Enter a signaling server address to get started.</p>
            <label className="mt-5 block text-[11px] font-semibold uppercase tracking-wider text-text-muted">Server</label>
            <input
              value={server}
              onChange={(e) => setServer(e.target.value)}
              className="mt-1 w-full rounded-[12px] border border-border bg-white px-4 py-2.5 text-sm text-text-primary outline-none focus:border-primary"
              spellCheck={false}
            />
            <label className="mt-4 block text-[11px] font-semibold uppercase tracking-wider text-text-muted">Port</label>
            <input
              value={port}
              onChange={(e) => setPort(e.target.value)}
              className="mt-1 w-full rounded-[12px] border border-border bg-white px-4 py-2.5 text-sm text-text-primary outline-none focus:border-primary"
              spellCheck={false}
            />
            <Button variant="primary" fullWidth className="mt-6" onClick={connect}>
              Connect
            </Button>
          </Card>
        )}

        {step === 1 && (
          <Card className="w-[420px] text-center">
            <div className="relative mx-auto flex h-20 w-20 items-center justify-center">
              {!ready ? (
                <>
                  <div className="dash-rotate absolute inset-0 rounded-full border-4 border-dashed border-primary" />
                  <IconLock className="h-8 w-8 text-primary" />
                </>
              ) : (
                <div className="step-in flex h-20 w-20 items-center justify-center rounded-full bg-success-50 text-success">
                  <IconShield className="h-9 w-9" />
                </div>
              )}
            </div>

            <div className="mt-4">
              {!ready ? (
                <>
                  <div className="text-lg font-semibold text-text-primary">Securing your account…</div>
                  <div className="mt-1 text-xs text-text-secondary">This only takes a moment</div>
                </>
              ) : (
                <div className="step-in">
                  <div className="text-lg font-semibold text-text-primary">Your account is ready ✓</div>
                  <div className="mt-1 text-xs text-text-secondary">Credentials successfully compiled</div>
                </div>
              )}
            </div>

            {ready && (
              <div className="step-in mt-6">
                <Button variant="success" fullWidth onClick={() => onNavigate("chat")}>
                  Get Started
                </Button>
                <Button variant="secondary" fullWidth className="mt-3">
                  Export Key Backup
                </Button>
              </div>
            )}
          </Card>
        )}
      </div>
    </div>
  );
}