/**
 * Shared size/speed formatting for the web UI.
 *
 * Binary (1024) steps with the conventional short labels the UI has always
 * shown. The ladder runs to EB so very large totals never index past the end
 * of the unit list (which used to render "1.1 undefined"); anything larger
 * stays in EB. Missing, NaN, infinite and negative inputs render as zero.
 */
const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'] as const;

export interface FormattedSize {
  value: string;
  unit: string;
}

export function formatBytesParts(bytes: number | null | undefined): FormattedSize {
  const n = typeof bytes === 'number' && Number.isFinite(bytes) && bytes > 0 ? bytes : 0;
  if (n < 1024) return { value: String(Math.round(n)), unit: 'B' };
  let i = Math.min(UNITS.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  let value = (n / 1024 ** i).toFixed(1);
  // 1048575 B is 1023.999 KB, which rounds to "1024.0 KB": show "1.0 MB".
  if (value === '1024.0' && i < UNITS.length - 1) {
    i += 1;
    value = (n / 1024 ** i).toFixed(1);
  }
  return { value, unit: UNITS[i] };
}

export function formatBytes(bytes: number | null | undefined): string {
  const { value, unit } = formatBytesParts(bytes);
  return `${value} ${unit}`;
}

export function formatSpeed(bytesPerSec: number | null | undefined): string {
  return `${formatBytes(bytesPerSec)}/s`;
}
