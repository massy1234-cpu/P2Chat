import { useState } from "react";
import ConnectScreen from "./components/ConnectScreen";
import RegisterScreen from "./components/RegisterScreen";
import ChatScreen from "./components/ChatScreen";
import SecurityScreen from "./components/SecurityScreen";

export type View = "connect" | "register" | "chat" | "security";
export type ConnState = "offline" | "connecting" | "online";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "connect", label: "Connect", icon: "M21 12a9 9 0 1 1-9-9" },
  { id: "register", label: "Register", icon: "M12 3v2m0 14v2M5.6 5.6l1.4 1.4m10.4 0l1.4-1.4M3 12h2m14 0h2" },
  { id: "chat", label: "Messages", icon: "M4 6h16v10H8l-4 4z" },
  { id: "security", label: "Security", icon: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z" },
];

export default function App() {
  const [view, setView] = useState<View>("connect");
  const [conn, setConn] = useState<ConnState>("offline");

  const status = {
    offline: { label: "Offline", color: "#64748b", dot: "bg-slate-500" },
    connecting: { label: "Connecting", color: "#fbbf24", dot: "bg-amber-400 pulse-dot" },
    online: { label: "Online · Tor", color: "#34d399", dot: "bg-emerald-400" },
  }[conn];

  return (
    <div className="grid h-full grid-cols-[240px_1fr]">
      <aside className="flex flex-col border-r border-edge bg-panel">
        <div className="flex items-center gap-3 px-5 pt-5 pb-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-400 to-violet-500 font-mono text-sm font-bold text-ink">
            P2
          </div>
          <div>
            <div className="text-sm font-semibold tracking-wide">P2Chat</div>
            <div className="font-mono text-[10px] text-muted">pqxdh · tor · pq</div>
          </div>
        </div>

        <nav className="mt-2 flex flex-col gap-1 px-3">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => setView(n.id)}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-left text-[13px] transition-colors ${
                view === n.id
                  ? "bg-edge/60 text-fg glow-ring"
                  : "text-muted hover:bg-edge/40 hover:text-fg"
              }`}
            >
              <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d={n.icon} />
              </svg>
              {n.label}
            </button>
          ))}
        </nav>

        <div className="mt-auto px-5 pb-5">
          <div className="rounded-xl border border-edge bg-panel-2 p-3">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${status.dot}`} />
              <span className="text-xs font-medium" style={{ color: status.color }}>
                {status.label}
              </span>
            </div>
            <div className="mt-2 font-mono text-[10px] leading-relaxed text-muted">
              151.48.81.210:9000
              <br />
              TLS 1.3 · X25519MLKEM768
            </div>
          </div>
        </div>
      </aside>

      <main className="relative overflow-hidden bg-ink">
        <div className="grid-bg pointer-events-none absolute inset-0" />
        <div className="relative h-full overflow-y-auto">
          {view === "connect" && <ConnectScreen conn={conn} setConn={setConn} />}
          {view === "register" && <RegisterScreen conn={conn} />}
          {view === "chat" && <ChatScreen />}
          {view === "security" && <SecurityScreen />}
        </div>
      </main>
    </div>
  );
}
