import { describe, expect, it } from 'vitest';

import { formatBytes, formatBytesParts, formatSpeed } from './format';

const KiB = 1024;

describe('formatBytes', () => {
  it('formats every binary unit up to EiB', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(KiB ** 2)).toBe('1.0 MB');
    expect(formatBytes(KiB ** 3)).toBe('1.0 GB');
    expect(formatBytes(KiB ** 4)).toBe('1.0 TB');
    expect(formatBytes(1.1 * KiB ** 5)).toBe('1.1 PB');
    expect(formatBytes(2 * KiB ** 6)).toBe('2.0 EB');
  });

  it('stays in EB beyond the largest unit instead of printing "undefined"', () => {
    expect(formatBytes(4096 * KiB ** 6)).toBe('4096.0 EB');
    expect(formatBytes(Number.MAX_VALUE)).not.toContain('undefined');
  });

  it('promotes a value that rounds up to 1024 into the next unit', () => {
    expect(formatBytes(KiB ** 2 - 1)).toBe('1.0 MB');
    expect(formatBytes(1023)).toBe('1023 B');
  });

  it('treats NaN, infinities, negatives and missing values as zero', () => {
    for (const v of [NaN, Infinity, -Infinity, -5, null, undefined]) {
      expect(formatBytes(v as number)).toBe('0 B');
    }
  });

  it('exposes value and unit separately for split stat cards', () => {
    expect(formatBytesParts(1.5 * KiB ** 4)).toEqual({ value: '1.5', unit: 'TB' });
    expect(formatBytesParts(0)).toEqual({ value: '0', unit: 'B' });
  });
});

describe('formatSpeed', () => {
  it('appends /s and shares the unit ladder', () => {
    expect(formatSpeed(0)).toBe('0 B/s');
    expect(formatSpeed(1024)).toBe('1.0 KB/s');
    expect(formatSpeed(5 * KiB ** 4)).toBe('5.0 TB/s');
    expect(formatSpeed(NaN)).toBe('0 B/s');
  });
});
