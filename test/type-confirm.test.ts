// Plan J sub-task J5 (DECISIONS #124, rulings B1, S9, S10, S14): the type question `npx pipegen` asks before it reads
// GitHub, and the `--type` values. Pure: a fake Prompter, hand-built services, no file and no network.
import { describe, expect, it, vi } from 'vitest';
import { PromptCancelledError, type Prompter } from '../src/cli/io.js';
import { confirmTypes, parseTypeFlags, TYPE_QUESTION } from '../src/cli/type-confirm.js';
import { emptyServiceQuality } from '../src/read/quality.js';
import type { Service, ServiceType } from '../src/types.js';

const svc = (over: Partial<Service> = {}): Service => ({
  name: 'app', path: '.', language: 'node', packageManager: 'npm', hasTests: true, envVars: [], dependsOn: [], scripts: [], frameworks: [], quality: emptyServiceQuality(), ...over,
});
const web = svc({ name: 'web', path: 'apps/web', projectType: { types: ['static-site'], evidence: ['output: "export" in apps/web/next.config.mjs'], unsure: false } });
const api = svc({ name: 'api', path: 'apps/api', projectType: { types: ['server'], evidence: ['runs as a server: a start script'], unsure: false } });
/** Control and bidi characters safeText removes. */
const UNSAFE = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;

/** A prompter that answers the yes/no question with `yes` and each select with the next of `picks`. */
function prompter(yes: boolean | Error, picks: (string | Error)[] = []) {
  const asked: string[] = [];
  const selects: { msg: string; values: string[]; def: string }[] = [];
  const p: Prompter = {
    confirm: vi.fn(async (msg: string, def: boolean) => {
      asked.push(msg);
      expect(def).toBe(true); // "(Y/n)": yes is the default
      if (yes instanceof Error) throw yes;
      return yes;
    }),
    select: vi.fn(async <T extends string>(msg: string, opts: { value: T; label: string }[], def: T) => {
      selects.push({ msg, values: opts.map((o) => o.value), def });
      const next = picks.shift();
      if (next instanceof Error) throw next;
      return next as T;
    }) as Prompter['select'],
    text: async () => { throw new Error('the type question asks no text'); },
  };
  return { p, asked, selects };
}

describe('confirmTypes (J5, #124)', () => {
  it('shows every service with its types and evidence, asks "Is this right? (Y/n)"; yes → no overrides', async () => {
    const { p, asked, selects } = prompter(true);
    expect(await confirmTypes(p, [web, api])).toEqual([]);
    expect(asked).toHaveLength(1);
    const msg = asked[0] as string;
    expect(msg.split('\n').at(-1)).toBe(TYPE_QUESTION);
    expect(TYPE_QUESTION).toBe('Is this right? (Y/n)');
    expect(msg).toContain('web: static-site (output: "export" in apps/web/next.config.mjs)');
    expect(msg).toContain('api: server (runs as a server: a start script)');
    expect(selects).toEqual([]);
  });

  it('an unsure type and a service with no type say so', async () => {
    const unsure = svc({ name: 'site', projectType: { types: ['server'], evidence: ['looks like a static site, but it has the server signs above'], unsure: true } });
    const py = svc({ name: 'worker', language: 'python', projectType: { types: [], evidence: [], unsure: false } });
    const { p, asked } = prompter(true);
    await confirmTypes(p, [unsure, py, svc({ name: 'bare' })]);
    expect(asked[0]).toContain('site: server, unsure (looks like a static site, but it has the server signs above)');
    expect(asked[0]).toContain('worker: none of static-site, library, cli, server, container');
    expect(asked[0]).toContain('bare: none of static-site, library, cli, server, container');
  });

  it('No → one select per service among the types plus "keep" (the default); picks become overrides by service name', async () => {
    const { p, selects } = prompter(false, ['keep', 'server']);
    expect(await confirmTypes(p, [web, api])).toEqual([{ service: 'api', type: 'server' }]);
    expect(selects).toHaveLength(2);
    for (const s of selects) {
      expect(s.values).toEqual(['keep', 'static-site', 'library', 'cli', 'server', 'container']);
      expect(s.def).toBe('keep');
    }
    expect(selects[0]?.msg).toContain('web');
    expect(selects[1]?.msg).toContain('api');
  });

  it('a cancel (Ctrl+C, Esc) at either question → "cancel"; any other error is not a cancel', async () => {
    expect(await confirmTypes(prompter(new PromptCancelledError()).p, [web])).toBe('cancel');
    expect(await confirmTypes(prompter(false, ['keep', new PromptCancelledError()]).p, [web, api])).toBe('cancel');
    await expect(confirmTypes(prompter(new Error('boom')).p, [web])).rejects.toThrow('boom');
  });

  it('no service → nothing asked, no overrides', async () => {
    const { p, asked } = prompter(true);
    expect(await confirmTypes(p, [])).toEqual([]);
    expect(asked).toEqual([]);
  });

  it('S14: service names and evidence are shown through safeText (no control or bidi character reaches the terminal)', async () => {
    const hostile = svc({ name: 'evil\u001b[2J\u202ename', projectType: { types: ['library'], evidence: ['bin in package.json\u0007\u001b]8;;http://x\u0007'], unsure: false } });
    const { p, asked, selects } = prompter(false, ['keep']);
    await confirmTypes(p, [hostile]);
    for (const line of (asked[0] as string).split('\n')) expect(line).not.toMatch(UNSAFE);
    expect(selects[0]?.msg).not.toMatch(UNSAFE);
    expect(asked[0]).toContain('evil');
  });

  it('a long list is cut with the --type hint, but every service still gets its select', async () => {
    const many = Array.from({ length: 40 }, (_, i) => svc({ name: `s${i}`, projectType: { types: ['server'], evidence: [], unsure: false } }));
    const { p, asked, selects } = prompter(false, many.map(() => 'keep'));
    await confirmTypes(p, many);
    expect(asked[0]).toContain('and 15 more services');
    expect(asked[0]).toContain('--type <service>=<type>');
    expect(selects).toHaveLength(40);
  });
});

describe('parseTypeFlags (J5, S10)', () => {
  it('a bare type and service=type; the service name may hold "=" and "/" (the type is after the last "=")', () => {
    expect(parseTypeFlags(['static-site'])).toEqual([{ service: null, type: 'static-site' }]);
    expect(parseTypeFlags(['web=static-site', '@o/api=server'])).toEqual([{ service: 'web', type: 'static-site' }, { service: '@o/api', type: 'server' }]);
    expect(parseTypeFlags(['a=b=cli'])).toEqual([{ service: 'a=b', type: 'cli' }]);
  });

  it('an unknown type or an empty service name is refused with a cleaned message naming the types', () => {
    for (const bad of ['website', 'web=', '=server', 'web=serv\u001b[31mer']) {
      const r = parseTypeFlags([bad]);
      expect(typeof r, bad).toBe('string');
      expect(r as string).not.toMatch(UNSAFE);
      expect(r as string).toContain('--type');
    }
    expect(parseTypeFlags(['website']) as string).toContain((['static-site', 'library', 'cli', 'server', 'container'] satisfies ServiceType[]).join(', '));
  });
});
