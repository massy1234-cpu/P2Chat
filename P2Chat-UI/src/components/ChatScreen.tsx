import { useEffect, useRef, useState } from "react";
import { CONTACTS, THREAD, type ChatContact, type ChatMessage } from "../data/chat";
import ContactCard from "./ContactCard";
import { IconChat, IconSend } from "./ui";

const REPLIES = [
  "Received — end-to-end encrypted ✓",
  "Got it. Connection stays secure.",
  "Thanks, your fingerprint matches.",
  "Encrypted and safe ✓",
];

function now(): string {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function ChatScreen() {
  const [active, setActive] = useState<ChatContact | null>(null);
  const [showCard, setShowCard] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>(THREAD);
  const [draft, setDraft] = useState("");
  const [typing, setTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const replyTimer = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (replyTimer.current) window.clearTimeout(replyTimer.current);
    },
    [],
  );

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages.length, typing]);

  const openContact = (c: ChatContact) => {
    setActive(c);
  };

  const send = () => {
    const text = draft.trim();
    if (!text || !active) return;
    setMessages((m) => [...m, { id: Date.now(), from: "me", text, time: now(), type: "CHAT_MESSAGE" }]);
    setDraft("");
    setTyping(true);
    replyTimer.current = window.setTimeout(() => {
      setMessages((m) => [...m, { id: Date.now() + 1, from: "them", text: REPLIES[Math.floor(Math.random() * REPLIES.length)], time: now(), type: "CHAT_MESSAGE" }]);
      setTyping(false);
    }, 1200);
  };

  return (
    <div className="relative flex h-full">
      <aside className="flex w-[300px] shrink-0 flex-col bg-sidebar">
        <div className="px-4 pt-4">
          <input
            placeholder="Search conversations..."
            className="w-full rounded-lg border border-border bg-white px-3 py-2 text-sm text-text-primary outline-none focus:border-primary"
          />
        </div>
        <div className="px-4 pt-3">
          <button className="w-full rounded-[12px] bg-gradient-to-br from-primary to-primary-dark py-2.5 text-sm font-semibold text-white shadow-[0_4px_12px_rgba(47,111,237,0.3)] transition-all hover:shadow-[0_6px_16px_rgba(47,111,237,0.4)] active:scale-[0.98]">
            <span className="inline-flex items-center justify-center gap-2">
              <IconChat className="h-4 w-4" />
              New Chat
            </span>
          </button>
        </div>
        <div className="mt-3 flex-1 space-y-2.5 overflow-y-auto px-4 pb-4">
          {CONTACTS.map((c) => (
            <button
              key={c.id}
              onClick={() => openContact(c)}
              className={`flex w-full items-center gap-3 rounded-2xl border border-transparent bg-white p-3 text-left shadow-[0_4px_14px_rgba(15,23,42,0.07)] transition-all duration-200 ${
                active?.id === c.id
                  ? "bg-primary-50/40 ring-2 ring-inset ring-primary/60"
                  : "hover:bg-primary-50/40"
              }`}
            >
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-primary-50 text-xs font-semibold text-primary">
                {c.avatar}
              </div>
              <div className="min-w-0 flex-1">
                <div className="truncate text-sm font-medium text-text-primary">{c.name}</div>
                <div className="truncate text-[11px] text-text-secondary">{c.lastMessage}</div>
              </div>
              <div className="flex shrink-0 flex-col items-end gap-1.5">
                <span className="text-[10px] text-text-muted">{c.time}</span>
                {c.unread > 0 && (
                  <span className="rounded-full bg-gradient-to-br from-primary to-primary-dark px-2 py-0.5 text-[10px] font-semibold text-white">{c.unread}</span>
                )}
              </div>
            </button>
          ))}
        </div>
      </aside>

      <section className="flex min-w-0 flex-1 flex-col bg-sidebar">
        {active ? (
          <>
            <div className="px-4 pt-4">
              <div className="flex items-center gap-3 rounded-2xl bg-white px-4 py-2.5 shadow-[0_4px_14px_rgba(15,23,42,0.07)]">
                <button
                  onClick={() => setShowCard(true)}
                  className="group flex min-w-0 flex-1 items-center gap-3 text-left"
                >
                  <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-primary-50 text-xs font-semibold text-primary">
                    {active.avatar}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-semibold text-text-primary group-hover:text-primary">{active.name}</div>
                    <div className="text-xs text-success-dark">{active.online ? "Online" : "Offline"}</div>
                  </div>
                </button>
                <button onClick={() => setShowCard(true)} className="group relative">
                  <svg viewBox="0 0 24 24" className="h-5 w-5 cursor-help text-success" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6z" />
                    <path d="M9 12l2 2 4-4" />
                  </svg>
                  <div className="pointer-events-none absolute right-0 top-full z-10 mt-2 hidden whitespace-nowrap rounded-lg bg-black/85 px-3 py-1.5 text-xs text-white group-hover:block">
                    Fully encrypted peer connection
                  </div>
                </button>
              </div>
            </div>

            <div ref={scrollRef} className="flex-1 space-y-3 overflow-y-auto px-6 py-5">
              {messages.map((m) => (
                <div
                  key={m.id}
                  className={`flex flex-col ${m.from === "me" ? "bubble-in-right items-end" : "bubble-in-left items-start"}`}
                >
                  <div
                    className={`max-w-[70%] rounded-[22px] px-4 py-2.5 text-sm leading-relaxed ${
                      m.from === "me"
                        ? "rounded-br-[6px] bg-gradient-to-br from-primary to-primary-dark text-white shadow-[0_6px_16px_rgba(47,111,237,0.25)]"
                        : "rounded-bl-[6px] bg-white text-text-primary shadow-[0_2px_10px_rgba(15,23,42,0.05)]"
                    }`}
                  >
                    {m.text}
                  </div>
                  <div className="mt-1 flex items-center gap-1 px-1 font-mono text-[10px] text-text-muted">
                    <span>{m.time}</span>
                    {m.from === "me" && <span className="text-primary">✓✓</span>}
                  </div>
                </div>
              ))}
              {typing && (
                <div className="flex flex-col bubble-in-left items-start">
                  <div className="flex items-center gap-1.5 rounded-[22px] rounded-bl-[6px] bg-white px-4 py-3 shadow-[0_2px_10px_rgba(15,23,42,0.05)]">
                    <span className="typing-dot h-2 w-2 rounded-full bg-text-muted" />
                    <span className="typing-dot h-2 w-2 rounded-full bg-text-muted" style={{ animationDelay: "0.2s" }} />
                    <span className="typing-dot h-2 w-2 rounded-full bg-text-muted" style={{ animationDelay: "0.4s" }} />
                  </div>
                </div>
              )}
            </div>

            <footer className="px-4 pb-4">
              <div className="flex items-center gap-2 rounded-2xl border border-border bg-white py-1.5 pl-3 pr-1.5 shadow-[0_4px_14px_rgba(15,23,42,0.06)]">
                <button
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-text-muted transition-colors hover:bg-black/5 hover:text-text-primary"
                  title="Attach"
                >
                  <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48" />
                  </svg>
                </button>
                <input
                  value={draft}
                  onChange={(e) => setDraft(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") send();
                  }}
                  placeholder="Type a message…"
                  className="flex-1 bg-transparent px-2 py-1.5 text-sm text-text-primary outline-none placeholder:text-text-muted"
                />
                <button
                  onClick={send}
                  disabled={!draft.trim()}
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary to-primary-dark text-white shadow-[0_4px_12px_rgba(47,111,237,0.35)] transition-all active:scale-95 ${
                    draft.trim()
                      ? "hover:scale-105 hover:shadow-[0_6px_16px_rgba(47,111,237,0.45)]"
                      : "cursor-not-allowed opacity-40 shadow-none"
                  }`}
                  title="Send"
                >
                  <IconSend className="h-4 w-4 -translate-x-px" />
                </button>
              </div>
            </footer>
          </>
        ) : (
          <div className="flex flex-1 flex-col items-center justify-center">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary-50 text-primary">
              <IconChat className="h-7 w-7" />
            </div>
            <div className="mt-4 text-sm font-semibold text-text-primary">Select a conversation</div>
            <div className="mt-1 max-w-[260px] text-center text-xs text-text-secondary">
              Choose a contact to open the encrypted thread and view their identity card
            </div>
          </div>
        )}
      </section>

      {showCard && active && (
        <>
          <div onClick={() => setShowCard(false)} className="card-fade absolute inset-0 z-10 bg-black/40 backdrop-blur-md" />
          <div className="card-in absolute right-0 top-0 z-20 flex h-full w-[320px] flex-col border-l border-border bg-sidebar shadow-[-12px_0_30px_rgba(15,23,42,0.12)]">
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <span className="text-sm font-semibold text-text-primary">Contact</span>
              <button
                onClick={() => setShowCard(false)}
                className="rounded-md p-1.5 text-text-muted transition-colors hover:bg-black/5 hover:text-text-primary"
              >
                <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                  <path d="M18 6L6 18M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="min-h-0 flex-1">
              <ContactCard contact={active} />
            </div>
          </div>
        </>
      )}
    </div>
  );
}