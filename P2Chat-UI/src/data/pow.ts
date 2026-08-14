export type PowLevelId = 1 | 2 | 3 | 4 | 5;

export interface PowLevel {
  level: PowLevelId;
  label: string;
  difficulty: number;
  memoryKB: number;
  timeCost: number;
  estimate: string;
  clients: string;
}

export const POW_PRESETS: PowLevel[] = [
  { level: 1, label: "trivial", difficulty: 8, memoryKB: 8 * 1024, timeCost: 1, estimate: "~1s", clients: "< 50" },
  { level: 2, label: "low", difficulty: 9, memoryKB: 16 * 1024, timeCost: 1, estimate: "~3.6s", clients: "< 150" },
  { level: 3, label: "medium", difficulty: 10, memoryKB: 32 * 1024, timeCost: 1, estimate: "~15s", clients: "< 300" },
  { level: 4, label: "high", difficulty: 11, memoryKB: 64 * 1024, timeCost: 2, estimate: "~2.2min", clients: "< 500" },
  { level: 5, label: "maximum", difficulty: 11, memoryKB: 128 * 1024, timeCost: 2, estimate: "~5min", clients: ">= 500" },
];

export const ARGON = {
  threads: 1,
  keyLen: 32,
  maxAttempts: 1 << 24,
};
