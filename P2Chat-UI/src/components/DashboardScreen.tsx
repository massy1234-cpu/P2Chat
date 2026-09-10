import type { ReactNode } from "react";
import type { View } from "../App";
import { Card, IconChat, IconLock, IconSettings, IconShield, IconTerminal } from "./ui";

function Protection({ items }: { items: string[] }) {
  return (
    <div className="w-[300px] shrink-0 rounded-2xl border border-white/15 bg-white/10 p-5 backdrop-blur-sm">
      <div className="flex items-center gap-2 text-white">
        <IconShield className="h-5 w-5" />
        <span className="text-sm font-semibold">Your protection</span>
      </div>
      <ul className="mt-3 space-y-2.5">
        {items.map((s) => (
          <li key={s} className="flex items-center gap-2 text-xs text-white/90">
            <span className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-emerald-400 text-white">
              <svg viewBox="0 0 24 24" className="h-2.5 w-2.5" fill="none" stroke="currentColor" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M20 6L9 17l-5-5" />
              </svg>
            </span>
            {s}
          </li>
        ))}
      </ul>
    </div>
  );
}

const PROTECTION = [
  "TLS 1.3 · X25519MLKEM768",
  "PQXDH ratchet active",
  "ML-KEM-768 + ML-DSA-87",
  "HSM keystore online",
];

const ACTIONS: { id: View; label: string; icon: ReactNode }[] = [
  { id: "setup", label: "Connect", icon: <IconSettings className="h-5 w-5" /> },
  { id: "chat", label: "New Chat", icon: <IconChat className="h-5 w-5" /> },
  { id: "security", label: "Security", icon: <IconShield className="h-5 w-5" /> },
];

const ACTIVITY = [
  { dot: "bg-emerald-500", text: "registration complete", time: "14:32:11" },
  { dot: "bg-primary", text: "session 0x0A initialized · Alice", time: "14:29" },
  { dot: "bg-primary", text: "message received · encrypted", time: "14:32" },
  { dot: "bg-amber-500", text: "mailbox 0x06 updated", time: "12:07" },
];

export default function DashboardScreen({ onNavigate }: { onNavigate: (v: View) => void }) {
  return (
    <div className="mx-auto max-w-5xl px-10 py-10">
      <header className="step-in">
        <h1 className="text-[26px] font-bold tracking-tight text-text-primary">Dashboard</h1>
        <p className="mt-1 text-sm text-text-secondary">A quick overview of your secure peer-to-peer network</p>
      </header>

      <div className="step-in relative mt-8 overflow-hidden rounded-[24px] bg-gradient-to-br from-primary to-primary-dark p-8 text-white">
        <div className="flex items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2 text-xs font-medium text-white/80">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              Online · Tor
            </div>
            <div className="mt-3 text-3xl font-bold">Welcome back</div>
            <div className="mt-1 text-sm text-white/80">Connected and fully protected.</div>
            <div className="mt-6 flex gap-8 [&>*+*]:border-l [&>*+*]:border-white/15 [&>*+*]:pl-6">
              <div>
                <div className="text-2xl font-bold">7</div>
                <div className="text-xs text-white/70">unread</div>
              </div>
              <div>
                <div className="text-2xl font-bold">3</div>
                <div className="text-xs text-white/70">chats</div>
              </div>
              <div>
                <div className="text-2xl font-bold">4</div>
                <div className="text-xs text-white/70">PQ keys</div>
              </div>
            </div>
          </div>
          <Protection items={PROTECTION} />
        </div>
      </div>

      <div className="step-in mt-6 grid grid-cols-3 gap-4" style={{ animationDelay: "60ms" }}>
        {ACTIONS.map((a) => (
          <button
            key={a.id}
            onClick={() => onNavigate(a.id)}
            className="flex items-center gap-3 rounded-2xl bg-white p-4 text-left shadow-[0_4px_14px_rgba(15,23,42,0.07)] transition-colors hover:bg-primary-50/40"
          >
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary-50 text-primary">{a.icon}</div>
            <span className="text-sm font-semibold text-text-primary">{a.label}</span>
          </button>
        ))}
      </div>

      <div className="step-in mt-4 grid grid-cols-3 gap-4" style={{ animationDelay: "100ms" }}>
        <Card>
          <div className="flex items-center gap-2 text-primary">
            <IconLock className="h-4 w-4" />
            <span className="text-sm font-semibold text-text-primary">Key material</span>
          </div>
          <div className="mt-2 text-2xl font-bold text-text-primary">4</div>
          <div className="mt-1 text-xs text-text-secondary">post-quantum keys · HSM active</div>
        </Card>
        <Card>
          <div className="flex items-center gap-2 text-primary">
            <IconChat className="h-4 w-4" />
            <span className="text-sm font-semibold text-text-primary">Contacts</span>
          </div>
          <div className="mt-2 text-2xl font-bold text-text-primary">3</div>
          <div className="mt-1 text-xs text-text-secondary">verified peer connections</div>
        </Card>
        <Card>
          <div className="flex items-center gap-2 text-primary">
            <IconShield className="h-4 w-4" />
            <span className="text-sm font-semibold text-text-primary">Session</span>
          </div>
          <div className="mt-2 text-2xl font-bold text-text-primary">TLS 1.3</div>
          <div className="mt-1 text-xs text-text-secondary">X25519MLKEM768 · PQXDH ready</div>
        </Card>
      </div>

      <Card className="step-in mt-6" >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-primary">
            <IconTerminal className="h-4 w-4" />
            <span className="text-sm font-semibold text-text-primary">Recent activity</span>
          </div>
          <button onClick={() => onNavigate("log")} className="text-xs font-medium text-primary transition-colors hover:text-primary-dark">
            View all
          </button>
        </div>
        <div className="mt-3 space-y-2 font-mono text-[11px]">
          {ACTIVITY.map((a, i) => (
            <div key={i} className="flex items-center gap-2.5">
              <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${a.dot}`} />
              <span className="flex-1 text-text-primary">{a.text}</span>
              <span className="text-text-muted">{a.time}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}