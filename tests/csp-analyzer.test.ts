import { describe, it, expect } from 'vitest';
import { parseCsp, analyzeCsp } from '../src/lib/csp-analyzer';

describe('parseCsp', () => {
  it('splits directives and sources', () => {
    const out = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline'");
    expect(out).toHaveLength(2);
    expect(out[0]).toEqual({ name: 'default-src', sources: ["'self'"] });
    expect(out[1]!.sources).toContain("'unsafe-inline'");
  });

  it('ignores trailing semicolons and extra whitespace', () => {
    expect(parseCsp("  default-src  'self' ;  ").length).toBe(1);
  });

  it('lowercases directive names', () => {
    expect(parseCsp("Default-SRC 'self'")[0]!.name).toBe('default-src');
  });
});

describe('analyzeCsp', () => {
  it('flags unsafe-inline in script-src as high', () => {
    const a = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-inline'");
    expect(a.findings.some((f) => f.id.startsWith('csp.unsafe-inline.script-src') && f.severity === 'high')).toBe(true);
  });

  it('flags unsafe-eval', () => {
    const a = analyzeCsp("script-src 'self' 'unsafe-eval'");
    expect(a.findings.some((f) => f.id.startsWith('csp.unsafe-eval') && f.severity === 'high')).toBe(true);
  });

  it('flags wildcard in script-src', () => {
    const a = analyzeCsp("script-src *");
    expect(a.findings.some((f) => f.id.startsWith('csp.wildcard.script-src'))).toBe(true);
  });

  it('flags scheme-only sources', () => {
    const a = analyzeCsp("default-src 'self'; script-src https:");
    expect(a.findings.some((f) => f.id.includes('scheme-source.script-src.https'))).toBe(true);
  });

  it('flags missing default-src', () => {
    const a = analyzeCsp("script-src 'self'");
    expect(a.findings.some((f) => f.id === 'csp.no-default-src')).toBe(true);
  });

  it('flags missing frame-ancestors', () => {
    const a = analyzeCsp("default-src 'self'");
    expect(a.findings.some((f) => f.id === 'csp.no-frame-ancestors')).toBe(true);
  });

  it('does not flag frame-ancestors when set to none', () => {
    const a = analyzeCsp("default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
    expect(a.findings.some((f) => f.id === 'csp.no-frame-ancestors')).toBe(false);
  });

  it('flags frame-ancestors wildcard', () => {
    const a = analyzeCsp("default-src 'self'; frame-ancestors *");
    expect(a.findings.some((f) => f.id === 'csp.frame-ancestors-wildcard' && f.severity === 'high')).toBe(true);
  });

  it('flags nonce + unsafe-inline combination as low', () => {
    const a = analyzeCsp("default-src 'self'; script-src 'self' 'nonce-abc123' 'unsafe-inline'");
    expect(a.findings.some((f) => f.id.startsWith('csp.nonce-and-unsafe-inline'))).toBe(true);
  });

  it('assigns grade A to a tight policy', () => {
    const a = analyzeCsp("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'; report-to csp-endpoint");
    expect(a.summary.grade).toBe('A');
    expect(a.summary.riskLevel).toBe('low');
  });

  it('assigns a low grade to a permissive policy', () => {
    const a = analyzeCsp("script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'");
    expect(['D', 'F']).toContain(a.summary.grade);
    expect(a.summary.riskLevel).toBe('high');
  });
});
