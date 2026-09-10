import { useState } from "react";
import DashboardScreen from "./components/DashboardScreen";
import SetupScreen from "./components/SetupScreen";
import ChatScreen from "./components/ChatScreen";
import SecurityScreen from "./components/SecurityScreen";
import LogScreen from "./components/LogScreen";
import { IconChat, IconChevronLeft, IconSettings } from "./components/ui";

export type View = "dashboard" | "setup" | "chat" | "security" | "log";
export type ConnState = "offline" | "connecting" | "online";

const NAV: { id: View; label: string; icon: string }[] = [
  { id: "dashboard", label: "Home", icon: "M3 9.5L12 3l9 6.5V20a1 1 0 0 1-1 1h-5v-7h-6v7H4a1 1 0 0 1-1-1z" },
  { id: "setup", label: "Setup", icon: "M18.36 6.64a9 9 0 1 1-12.73 0M12 2v10" },
  { id: "chat", label: "Messages", icon: "M4 6h16v10H8l-4 4z" },
  { id: "security", label: "Security", icon: "M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6z" },
  { id: "log", label: "Log", icon: "M4 17l6-6-6-6M12 19h8" },
];

const EASE = "transition-[max-width,opacity] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)]";

export default function App() {
  const [view, setView] = useState<View>("dashboard");
  const [conn] = useState<ConnState>("online");
  const [collapsed, setCollapsed] = useState(false);

  const status = {
    offline: { label: "Offline", color: "#6b7280", dot: "bg-slate-400", bg: "bg-slate-100" },
    connecting: { label: "Connecting", color: "#b45309", dot: "bg-amber-500 pulse-dot", bg: "bg-amber-50" },
    online: { label: "Online", color: "#0f7a38", dot: "bg-emerald-500", bg: "bg-success-50" },
  }[conn];

  const labelClass = (on: boolean) =>
    `${EASE} overflow-hidden whitespace-nowrap ${on ? "max-w-40 opacity-100" : "max-w-0 opacity-0"}`;

  return (
    <div className="flex h-full">
      <aside
        className={`flex shrink-0 flex-col overflow-hidden border-r border-border bg-sidebar transition-[width] duration-500 ease-[cubic-bezier(0.22,1,0.36,1)] ${
          collapsed ? "w-[68px]" : "w-[240px]"
        }`}
      >
        <div className="flex items-center justify-between pt-6 pb-5 px-3">
          <button onClick={() => setCollapsed((c) => !c)} className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] bg-gradient-to-br from-primary to-primary-dark text-white shadow-[0_4px_12px_rgba(47,111,237,0.35)]">
              <IconChat className="h-5 w-5" />
            </div>
            <span className={labelClass(!collapsed)}>
              <span className="text-lg font-bold tracking-wide text-text-primary">P2Chat</span>
            </span>
          </button>
          <button
            onClick={() => setCollapsed(true)}
            className={`rounded-md p-1.5 text-text-muted transition-colors hover:bg-black/5 hover:text-text-primary ${
              collapsed ? "hidden" : ""
            }`}
          >
            <IconChevronLeft />
          </button>
        </div>

        <nav className="mt-2 flex flex-col gap-1 px-3">
          {NAV.map((n) => {
            const active = view === n.id;
            return (
              <button
                key={n.id}
                onClick={() => setView(n.id)}
                className={`flex w-full items-center rounded-[10px] px-3 py-2 text-left text-[13px] transition-all duration-200 ${
                  collapsed ? "gap-0" : "gap-3"
                } ${
                  active
                    ? "bg-gradient-to-r from-primary to-primary-dark font-semibold text-white shadow-[0_4px_12px_rgba(47,111,237,0.3)]"
                    : "font-medium text-text-secondary hover:bg-black/5 hover:text-text-primary"
                } ${collapsed ? "w-fit" : "w-full"}`}
              >
                <svg viewBox="0 0 24 24" className="h-4 w-4 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d={n.icon} />
                </svg>
                <span className={labelClass(!collapsed)}>{n.label}</span>
              </button>
            );
          })}
        </nav>

        <div className={`mt-auto space-y-3 pb-6 px-5`}>
          <div className={`flex items-center gap-2 rounded-full ${status.bg} px-4 py-2`}>
            <span className={`h-2 w-2 shrink-0 rounded-full ${status.dot}`} />
            <span className={`${labelClass(!collapsed)} text-xs font-semibold`} style={{ color: status.color }}>
              {status.label}
            </span>
          </div>
          <button className={`flex w-full items-center gap-3 rounded-[10px] px-3 py-2 text-left text-[13px] font-medium transition-colors hover:bg-black/5 hover:text-text-primary`}>
            <IconSettings className="h-5 w-5 shrink-0" />
            <span className={labelClass(!collapsed)}>Settings</span>
          </button>
        </div>
      </aside>

      <main className="relative flex-1 overflow-hidden bg-ink">
        <div key={view} className="view-in relative h-full overflow-y-auto">
          {view === "dashboard" && <DashboardScreen onNavigate={setView} />}
          {view === "setup" && <SetupScreen onNavigate={setView} />}
          {view === "chat" && <ChatScreen />}
          {view === "security" && <SecurityScreen />}
          {view === "log" && <LogScreen />}
        </div>
      </main>
    </div>
  );
}