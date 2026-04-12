export interface BenchmarkRow {
  repo: string;
  files: number;
  foxguard: number;
  semgrep: number;
  opengrep: number | null;
}

export const benchmarkRows: BenchmarkRow[] = [
  { repo: 'express', files: 141, foxguard: 0.276, semgrep: 6.086, opengrep: null },
  { repo: 'flask', files: 83, foxguard: 0.333, semgrep: 6.509, opengrep: null },
  { repo: 'gin', files: 99, foxguard: 0.499, semgrep: 4.952, opengrep: null },
];

export const benchmarkMax = Math.max(
  ...benchmarkRows.flatMap((row) => [row.foxguard, row.semgrep, row.opengrep ?? 0])
);

export function timeWidth(seconds: number | null): number {
  if (seconds === null) return 0;
  return Math.max((seconds / benchmarkMax) * 100, 2);
}

export function speedMultiplier(row: BenchmarkRow): string {
  return Math.round(row.semgrep / row.foxguard).toLocaleString() + 'x';
}
