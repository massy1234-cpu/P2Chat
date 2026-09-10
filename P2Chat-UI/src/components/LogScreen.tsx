import { Card, IconTerminal } from "./ui";

type Level = "DEBUG" | "INFO" | "WARNING" | "ERROR";

const LOGS: { time: string; level: Level; msg: string }[] = [
  { time: "14:32:01", level: "INFO", msg: "tor bootstrapped, circuit established" },
  { time: "14:32:02", level: "INFO", msg: "TLS 1.3 handshake complete · PQ key exchange (X25519MLKEM768)" },
  { time: "14:32:03", level: "DEBUG", msg: "yamux session open · stream ID 1" },
  { time: "14:32:04", level: "DEBUG", msg: "session listener + writer up · tag 0x00 registered" },
  { time: "14:32:05", level: "INFO", msg: "RegisterTokenReq (0x01) sent to server" },
  { time: "14:32:06", level: "INFO", msg: "PowToken (0x02) received · difficulty Level 2" },
  { time: "14:32:06", level: "DEBUG", msg: "argon2id · memory 16384 KB · time 1 · threads 1" },
  { time: "14:32:09", level: "INFO", msg: "PoW solved at nonce 7200 · zero-bits satisfied" },
  { time: "14:32:09", level: "INFO", msg: "ChallengeResponse (0x03) sent to server" },
  { time: "14:32:10", level: "INFO", msg: "blind signature received · TokenEmission (0x05)" },
  { time: "14:32:10", level: "DEBUG", msg: "unblind() applied · token = BLS G1 (48 bytes)" },
  { time: "14:32:11", level: "INFO", msg: "registration complete · ready to publish bundle" },
];

const LEVEL_STYLE: Record<Level, string> = {
  DEBUG: "text-text-muted",
  INFO: "text-primary",
  WARNING: "text-amber-600",
  ERROR: "text-rose-600",
};

const LEVEL_DOT: Record<Level, string> = {
  DEBUG: "bg-slate-300",
  INFO: "bg-primary",
  WARNING: "bg-amber-500",
  ERROR: "bg-rose-500",
};

const LEVELS: Level[] = ["ERROR", "WARNING", "INFO", "DEBUG"];

export default function LogScreen() {
  return (
    <div className="mx-auto max-w-5xl px-10 py-10">
      <header className="step-in flex items-end justify-between">
        <div>
          <h1 className="text-[26px] font-bold tracking-tight text-text-primary">Application Log</h1>
          <p className="mt-1 text-sm text-text-secondary">Every event of the application, in real time</p>
        </div>
        <button className="rounded-[10px] border border-border bg-white px-3 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:bg-black/5">
          Clear
        </button>
      </header>

      <Card className="step-in mt-8" >
        <div className="flex items-center justify-between border-b border-border pb-3">
          <div className="flex items-center gap-4 text-[11px] font-medium uppercase tracking-wider text-text-muted">
            <IconTerminal className="h-4 w-4 text-primary" />
            {LEVELS.map((lv) => (
              <span key={lv} className="flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${LEVEL_DOT[lv]}`} />
                {lv}
              </span>
            ))}
          </div>
          <span className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-success-dark">
            <span className="pulse-dot h-2 w-2 rounded-full bg-emerald-500" />
            Live
          </span>
        </div>
        <div className="mt-3 max-h-[62vh] space-y-0.5 overflow-y-auto font-mono text-xs">
          {LOGS.map((l, i) => (
            <div key={i} className="flex items-start gap-3 rounded-md px-2 py-1 transition-colors hover:bg-black/5">
              <span className="shrink-0 text-text-muted">{l.time}</span>
              <span className={`flex shrink-0 items-center gap-1.5 font-semibold ${LEVEL_STYLE[l.level]}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${LEVEL_DOT[l.level]}`} />
                {l.level}
              </span>
              <span className="text-text-primary">{l.msg}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}