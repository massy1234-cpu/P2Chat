import { useEffect, useRef, useState } from "react";
import type { ConnState } from "../App";
import { POW_PRESETS, ARGON, type PowLevelId } from "../data/pow";
import { CLIENT_PHASES } from "../data/phases";

type StepStatus = "pending" | "active" | "done" | "error";

const hex = (n: number) =>
  Array.from({ length: n }, () => Math.floor(Math.random() * 256).toString(16).padStart(2, "0")).join(" ");

export default function RegisterScreen({ conn }: { conn: ConnState }) {
  const [phaseId, setPhaseId] = useState(-1);
  const [statuses, setStatuses] = useState<StepStatus[]>(CLIENT_PHASES.map(() => "pending"));
  const [level] = useState<PowLevelId>(2);
  const [attempts, setAttempts] = useState(0);
  const [nonce, setNonce] = useState<string | null>(null);
  const [blinded, setBlinded] = useState<string | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [run, setRun] = useState(false);
  const timer = useRef<number | null>(null);

  useEffect(() => () => {
    if (timer.current) window.clearInterval(timer.current);
  }, []);

  const pow = POW_PRESETS.find((p) => p.level === level)!;

  const start = () => {
    if (run) return;
    setRun(true);
    setStatuses(CLIENT_PHASES.map(() => "pending"));
    setNonce(null);
    setBlinded(null);
    setToken(null);
    setAttempts(0);
    setPhaseId(0);
    setStatuses((s) => s.map((st, i) => (i === 0 ? "active" : st)));

    let step = 0;
    let nonceVal = 0;
    const tick = () => {
      if (step === 0) {
        setStatuses((s) => s.map((st, i) => (i === 0 ? "done" : i === 1 ? "active" : st)));
        setPhaseId(1);
        step = 1;
        return 1300;
      }
      if (step === 1) {
        setStatuses((s) => s.map((st, i) => (i === 1 ? "done" : i === 2 ? "active" : st)));
        setPhaseId(2);
        step = 2;
        return 400;
      }
      if (step === 2) {
        nonceVal += Math.floor(1 + Math.random() * 9);
        setAttempts(nonceVal);
        return 60;
      }
      return 60;
    };

    timer.current = window.setInterval(() => {
      if (step === 2) {
        nonceVal += Math.floor(1 + Math.random() * 12);
        setAttempts(nonceVal);
        if (nonceVal >= 7200) {
          if (timer.current) window.clearInterval(timer.current);
          setNonce(nonceVal.toFixed(0));
          setStatuses((s) => s.map((st, i) => (i === 2 ? "done" : i === 3 ? "active" : st)));
          setPhaseId(3);
          setBlinded(hex(48));
          step = 3;
          timer.current = window.setInterval(() => {
            if (step === 3) {
              if (timer.current) window.clearInterval(timer.current);
              setStatuses((s) => s.map((st, i) => (i === 3 ? "done" : i === 4 ? "active" : st)));
              setPhaseId(4);
              setToken(hex(48));
              step = 4;
            } else if (step === 4) {
              if (timer.current) window.clearInterval(timer.current);
              setStatuses((s) => s.map((st, i) => (i === 4 ? "done" : st)));
              setPhaseId(5);
            }
          }, 1600);
        }
      }
    }, tick());
  };

  const connected = conn === "online";

  return (
    <div className="mx-auto min-h-full max-w-6xl px-10 py-10">
      <header className="step-in flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Registration</h1>
          <p className="mt-1 text-sm text-muted">
            Token registration: PoW (Argon2id) + Blind BLS challenge-response, driven by the router state machine.
          </p>
        </div>
        <button
          onClick={start}
          disabled={run || !connected}
          className={`rounded-xl px-4 py-2 text-sm font-semibold transition-all ${
            run
              ? "cursor-default bg-edge/60 text-muted"
              : !connected
                ? "cursor-not-allowed bg-edge/40 text-muted/50"
                : "bg-gradient-to-r from-cyan-500/20 to-violet-500/20 text-fg hover:from-cyan-500/30 hover:to-violet-500/30 glow-ring"
          }`}
        >
          {run ? "Registering…" : connected ? "Start registration" : "Connect first"}
        </button>
      </header>

      <div className="step-in mt-8 grid grid-cols-[1fr_360px] gap-6" style={{ animationDelay: "60ms" }}>
        <div className="flex flex-col gap-3">
          {CLIENT_PHASES.map((p, i) => {
            const st = statuses[i];
            return (
              <div
                key={p.id}
                className={`glass rounded-2xl px-5 py-4 transition-all duration-300 ${st === "active" ? "glow-ring border-cyan-glow/40" : ""} ${
                  st === "pending" ? "opacity-45" : ""
                } ${st === "done" ? "opacity-95" : ""}`}
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`h-2 w-2 shrink-0 rounded-full ${
                      st === "done" ? "bg-emerald-400" : st === "active" ? "bg-cyan-glow pulse-dot" : st === "error" ? "bg-rose-400" : "bg-slate-600"
                    }`}
                  />
                  <span className="rounded-md border border-edge bg-panel-2 px-2 py-0.5 font-mono text-[11px] text-cyan-glow/90">{p.bytecode}</span>
                  <span className="text-sm font-semibold">{p.name}</span>
                  <span className="ml-auto rounded-md border border-edge px-2 py-0.5 text-[10px] text-muted">{p.dir}</span>
                </div>
                <p className="mt-2 pl-5 text-xs leading-relaxed text-muted">{p.desc}</p>

                {p.id === "challenge" && phaseId >= 1 && (
                  <div className="mt-3 flex flex-wrap items-center gap-2 pl-5">
                    {[1, 2, 3, 4, 5].map((lv) => (
                      <span
                        key={lv}
                        className={`rounded-md px-2 py-0.5 font-mono text-[11px] transition-colors ${
                          lv === level
                            ? "bg-amber-400/15 text-amber-300 border border-amber-400/30"
                            : "border border-edge text-muted"
                        }`}
                      >
                        L{lv}
                      </span>
                    ))}
                    <span className="font-mono text-[11px] text-amber-300/90">
                      load_report · {pow.clients} clients → Level {level}
                    </span>
                  </div>
                )}

                {p.id === "proof" && phaseId >= 2 && (
                  <div className="mt-3 space-y-1 pl-5 font-mono text-[11px] text-muted">
                    <div>argon2id · memory {pow.memoryKB} KB · time {pow.timeCost} · threads {ARGON.threads} · keyLen {ARGON.keyLen} B</div>
                    <div>
                      difficulty {pow.difficulty} leading zero bits · maxAttempts {ARGON.maxAttempts.toLocaleString()}
                    </div>
                    <div className="text-cyan-glow/90">zero-bits satisfied at nonce {attempts > 0 ? nonce ?? attempts.toLocaleString() : "…"} ({pow.estimate})</div>
                  </div>
                )}

                {p.id === "blind" && blinded && (
                  <div className="mt-3 pl-5">
                    <div className="font-mono text-[11px] text-muted">
                      M' = blind(msg) · G1 compressed, 48 bytes sent as 0x04
                    </div>
                    <div className="mt-1 break-all font-mono text-[10px] leading-relaxed text-violet-glow/80">{blinded}</div>
                  </div>
                )}

                {p.id === "token" && token && (
                  <div className="mt-3 pl-5">
                    <div className="font-mono text-[11px] text-emerald-400/90">token = unblind(sig) · BLS G1, registration completed</div>
                    <div className="mt-1 break-all font-mono text-[10px] leading-relaxed text-emerald-300/80">{token}</div>
                  </div>
                )}
              </div>
            );
          })}

          {phaseId === 5 && (
            <div className="step-in glass rounded-2xl border-emerald-400/30 p-5 text-center">
              <div className="text-sm font-semibold text-emerald-300">Token obtained — ready to publish PublicBundle + IK ML-DSA</div>
              <div className="mt-1 text-xs text-muted">Next: REGISTER_REQ (0x01) with UserID (32B) + PQXDH PublicBundle + ML-DSA signature</div>
            </div>
          )}
        </div>

        <div className="glass h-fit rounded-2xl p-5">
          <div className="text-[11px] font-medium uppercase tracking-wider text-muted">State machine</div>
          <div className="mt-3 flex flex-col gap-2">
            {["stateAwaitChallenge", "stateAwaitToken", "stateCompleted", "stateFailed"].map((s, i) => (
              <div
                key={s}
                className={`rounded-lg border px-3 py-2 font-mono text-[11px] ${
                  phaseId === 5 && i === 2
                    ? "border-emerald-400/40 bg-emerald-400/10 text-emerald-300"
                    : phaseId === 4
                      ? i === 1
                        ? "border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow"
                        : "border-edge text-muted"
                      : phaseId === -1
                        ? "border-edge text-muted/70"
                        : i === 0
                          ? "border-cyan-glow/40 bg-cyan-glow/10 text-cyan-glow"
                          : "border-edge text-muted/70"
                }`}
              >
                {s}
              </div>
            ))}
          </div>
          <div className="mt-4 space-y-1 border-t border-edge pt-4 font-mono text-[10px] leading-relaxed text-muted">
            <div>0x01 RegisterTokenReq → server</div>
            <div>0x02 PowToken ← challenge</div>
            <div>0x03 nonce + 0x04 M' → server</div>
            <div>0x05 TokenEmission ← sig</div>
          </div>
        </div>
      </div>
    </div>
  );
}
