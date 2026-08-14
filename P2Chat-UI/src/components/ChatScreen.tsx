import { useState } from "react";
import { CONTACTS, THREAD, type ChatContact } from "../data/chat";

const TYPE_COLORS: Record<string, string> = {
  SESSION_INIT: "text-violet-glow border-violet-glow/30 bg-violet-glow/10",
  MAILBOX_PUT: "text-amber-300 border-amber-400/30 bg-amber-400/10",
  CHAT_MESSAGE: "text-cyan-glow border-cyan-glow/30 bg-cyan-glow/10",
  FRIEND_REQUEST: "text-emerald-300 border-emerald-400/30 bg-emerald-400/10",
};

const VERIFIED_LABEL: Record<ChatContact["verified"], string> = {
  "ml-dsa": "ML-DSA-87",
  xeddsa: "XEdDSA",
  none: "pending",
};

export default function ChatScreen() {
  const [active, setActive] = useState(CONTACTS[0]);

  return (
    <div className="flex h-full">
      <aside className="flex w-[300px] shrink-0 flex-col border-r border-edge bg-panel">
        <div className="border-b border-edge px-5 py-4">
          <div className="text-sm font-semibold">Conversations</div>
          <input
            placeholder="Search…"
            className="mt-3 w-full rounded-lg border border-edge bg-ink px-3 py-1.5 font-mono text-xs text-fg outline-none focus:border-cyan-glow/50"
          />
        </div>
        <div className="flex-1 overflow-y-auto">
          {CONTACTS.map((c) => (
            <button
              key={c.id}
              onClick={() => setActive(c)}
              className={`flex w-full items-start gap-3 px-5 py-3 text-left transition-colors ${
                active.id === c.id ? "bg-edge/50" : "hover:bg-edge/30"
              }`}
            >
              <div className="relative shrink-0">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-edge-2 to-panel-2 text-xs font-semibold">
                  {c.avatar}
                </div>
                {c.online && <span className="absolute -right-0.5 -bottom-0.5 h-3 w-3 rounded-full border-2 border-panel bg-emerald-400" />}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="truncate text-sm font-medium">{c.name}</span>
                  <span className="shrink-0 font-mono text-[10px] text-muted">{c.time}</span>
                </div>
                <div className="mt-0.5 flex items-center gap-2">
                  <span className="truncate font-mono text-[11px] text-muted">{c.lastMessage}</span>
                  {c.pqxdh && (
                    <span className="shrink-0 rounded border border-edge px-1 font-mono text-[9px] text-muted">PQXDH</span>
                  )}
                </div>
                <div className="mt-1 flex items-center gap-1.5">
                  {c.mailbox && (
                    <span className="rounded bg-amber-400/10 px-1.5 py-px font-mono text-[9px] text-amber-300">0x06 mailbox</span>
                  )}
                  <span
                    className={`rounded px-1.5 py-px font-mono text-[9px] ${
                      c.verified === "ml-dsa"
                        ? "bg-emerald-400/10 text-emerald-300"
                        : c.verified === "xeddsa"
                          ? "bg-cyan-glow/10 text-cyan-glow"
                          : "bg-slate-500/10 text-muted"
                    }`}
                  >
                    {VERIFIED_LABEL[c.verified]}
                  </span>
                  {c.unread > 0 && (
                    <span className="ml-auto rounded-full bg-cyan-glow/20 px-1.5 py-px font-mono text-[9px] text-cyan-glow">{c.unread}</span>
                  )}
                </div>
              </div>
            </button>
          ))}
        </div>
        <div className="border-t border-edge px-5 py-3">
          <button className="w-full rounded-lg border border-dashed border-edge py-2 text-xs text-muted transition-colors hover:border-cyan-glow/40 hover:text-fg">
            + New conversation (FRIEND_REQUEST 0x09)
          </button>
        </div>
      </aside>

      <section className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center gap-3 border-b border-edge bg-panel px-6 py-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-edge-2 to-panel-2 text-xs font-semibold">
            {active.avatar}
          </div>
          <div>
            <div className="text-sm font-semibold">{active.name}</div>
            <div className="flex items-center gap-2 font-mono text-[10px] text-muted">
              <span>{active.handle}</span>
              {active.online && <span className="text-emerald-400">● online</span>}
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2 font-mono text-[10px]">
            <span className="rounded border border-edge bg-panel-2 px-2 py-1 text-cyan-glow">0x0B CHAT_MESSAGE</span>
            <span className="rounded border border-edge bg-panel-2 px-2 py-1 text-violet-glow">PQXDH</span>
          </div>
        </header>

        <div className="flex-1 space-y-4 overflow-y-auto px-6 py-5">
          {THREAD.map((m) => (
            <div key={m.id} className={`flex flex-col ${m.from === "me" ? "items-end" : "items-start"}`}>
              <div
                className={`max-w-[70%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
                  m.from === "me" ? "rounded-br-sm bg-gradient-to-br from-cyan-500/15 to-violet-500/15 border border-cyan-glow/15" : "glass"
                }`}
              >
                <div>{m.text}</div>
              </div>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5 px-1">
                {m.security?.map((s) => (
                  <span key={s} className={`rounded border px-1.5 py-px font-mono text-[9px] ${TYPE_COLORS[m.type] ?? "border-edge text-muted"}`}>
                    {s}
                  </span>
                ))}
                <span className="font-mono text-[10px] text-muted/70">{m.time}</span>
              </div>
            </div>
          ))}
        </div>

        <footer className="border-t border-edge bg-panel px-6 py-4">
          <div className="flex items-center gap-3">
            <button className="rounded-lg border border-edge px-3 py-2 text-xs text-muted transition-colors hover:text-fg">+ attach</button>
            <input
              placeholder="Type a message… (encrypted end-to-end)"
              className="flex-1 rounded-lg border border-edge bg-ink px-4 py-2.5 text-sm text-fg outline-none focus:border-cyan-glow/50"
            />
            <button className="rounded-lg bg-gradient-to-r from-cyan-500/25 to-violet-500/25 px-4 py-2.5 text-sm font-semibold text-fg transition-all hover:from-cyan-500/35 hover:to-violet-500/35 glow-ring">
              Send
            </button>
          </div>
          <div className="mt-2 flex items-center gap-2 font-mono text-[10px] text-muted">
            <span className="text-emerald-400">◆</span> ratchet active · ML-KEM-768 shared · X25519 fallback · AES-256-GCM
          </div>
        </footer>
      </section>
    </div>
  );
}
