import type { ChatContact } from "../data/chat";
import { Button, IconShield } from "./ui";

function qrPattern(seed: string, size = 21): boolean[][] {
  let h = 2166136261;
  for (const ch of seed) {
    h ^= ch.charCodeAt(0);
    h = Math.imul(h, 16777619);
  }
  const grid = Array.from({ length: size }, () => Array<boolean>(size).fill(false));
  const finder = (r: number, c: number) => {
    for (let i = 0; i < 7; i++)
      for (let j = 0; j < 7; j++) {
        const on = i === 0 || i === 6 || j === 0 || j === 6 || (i >= 2 && i <= 4 && j >= 2 && j <= 4);
        grid[r + i][c + j] = on;
      }
  };
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);
  for (let i = 0; i < size; i++)
    for (let j = 0; j < size; j++) {
      if (grid[i][j]) continue;
      if ((i < 8 && j < 8) || (i < 8 && j >= size - 8) || (i >= size - 8 && j < 8)) continue;
      h ^= i * 31 + j;
      h = Math.imul(h, 16777619);
      grid[i][j] = (h & 1) === 1;
    }
  return grid;
}

export default function ContactCard({ contact }: { contact: ChatContact }) {
  const grid = qrPattern(contact.publicId);
  const firstName = contact.name.split(" ")[0];

  return (
    <div className="flex h-full flex-col items-center overflow-y-auto px-5 py-6">
      <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary-50 text-lg font-semibold text-primary">
        {contact.avatar}
      </div>
      <div className="mt-3 text-base font-semibold text-text-primary">{contact.name}</div>
      <div className="mt-1 flex items-center gap-1 text-xs font-medium text-success-dark">
        <IconShield className="h-3.5 w-3.5" />
        {contact.verified === "none" ? "Pending verification" : "Verified"}
      </div>
      <div className="mt-0.5 font-mono text-[10px] text-text-muted">{contact.handle} · added {contact.addedOn}</div>

      <div className="mt-6 w-full rounded-2xl bg-white p-4 shadow-[0_4px_14px_rgba(15,23,42,0.07)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_8px_20px_rgba(15,23,42,0.1)]">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Identity</div>
        <div className="mt-2 break-all font-mono text-[10px] leading-relaxed text-text-primary">{contact.fingerprint}</div>
      </div>

      <div className="mt-3 w-full rounded-2xl bg-white p-4 shadow-[0_4px_14px_rgba(15,23,42,0.07)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_8px_20px_rgba(15,23,42,0.1)]">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Public bundle</div>
        <div className="mt-2 space-y-1.5">
          {contact.bundle.map((b) => (
            <div key={b.label} className="flex items-center justify-between gap-2 text-xs">
              <span className="text-text-secondary">{b.label}</span>
              <span className="shrink-0 font-mono text-[10px] text-primary">{b.value}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="mt-3 w-full rounded-2xl bg-white p-4 text-center shadow-[0_4px_14px_rgba(15,23,42,0.07)] transition-all duration-200 hover:-translate-y-0.5 hover:shadow-[0_8px_20px_rgba(15,23,42,0.1)]">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-text-muted">Verify identity</div>
        <div className="mx-auto mt-3 rounded-lg bg-white p-2" style={{ width: 168, height: 168 }}>
          <div className="grid" style={{ gridTemplateColumns: `repeat(${grid.length}, 1fr)` }}>
            {grid.flatMap((row, i) =>
              row.map((on, j) => <div key={`${i}-${j}`} className={on ? "bg-black/85" : ""} />),
            )}
          </div>
        </div>
        <div className="mt-2 text-[10px] text-text-muted">Scan to confirm this is really {firstName}</div>
      </div>

      <div className="mt-4 flex w-full flex-col gap-2">
        <Button variant="primary" fullWidth>
          Share Bundle
        </Button>
        <Button variant="secondary" fullWidth className="text-rose-600 transition-colors hover:bg-rose-50">
          Remove Contact
        </Button>
      </div>
    </div>
  );
}