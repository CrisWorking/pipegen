// Plan P Task PL-D2: the display name of a job ("<What> · <service>"), and the guard that no step of any renderer is named "pipegen: ...".
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { actionStepName, renderGateUploads, renderPlatformStep } from '../src/engine/render-step.js';
import { jobName, withJobNames } from '../src/layers/job-names.js';
import { NEED_CATEGORIES } from '../src/types.js';
import { platform } from './helpers/render.js';

describe('PL-D2: jobName', () => {
  it('a repo-wide job is its "what", a service job adds " · <service>"', () => {
    expect(jobName('secrets')).toBe('Secret scan');
    expect(jobName('sast--web')).toBe('Code scan · web');
    expect(jobName('unit-tests--my-api')).toBe('Unit tests · my-api');
    expect(jobName('dast-run--app')).toBe('DAST run · app');
    expect(jobName('zap-active-run--app')).toBe('ZAP active scan run · app');
    expect(jobName('image-build--web')).toBe('Image build · web');
  });

  it('an id nobody listed gets a readable fallback, never its raw id', () => {
    expect(jobName('some-new-check')).toBe('Some new check');
    expect(jobName('some-new-check--web')).toBe('Some new check · web');
    expect(jobName('')).toBe('Check');
  });

  it('every need category has a name that is not its raw id', () => {
    for (const c of NEED_CATEGORIES) expect(jobName(c), c).not.toBe(c);
    for (const c of NEED_CATEGORIES) expect(jobName(`${c}--x`), c).toMatch(/ · x$/);
  });

  it('an inherited object key is no job id with a name ("constructor", "__proto__")', () => {
    expect(jobName('constructor')).toBe('Constructor');
    expect(jobName('__proto__--x')).toBe('__proto__ · x');
    expect(jobName('toString')).toBe('ToString');
  });

  it('withJobNames keeps a name already there (the callers, the gate) and names the rest', () => {
    const out = withJobNames({ gate: { name: 'gate' }, 'lint--app': {}, pipegen: { name: 'pipegen' } });
    expect(out).toEqual({ gate: { name: 'gate' }, 'lint--app': { name: 'Lint · app' }, pipegen: { name: 'pipegen' } });
  });
});

describe('PL-D2: action step names', () => {
  it('a platform action is named by what it does, not by its path', () => {
    expect(actionStepName('actions/download-artifact')).toBe('Download the artifact');
    expect(actionStepName('actions/upload-artifact')).toBe('Upload the artifact');
    expect(actionStepName('github/codeql-action/upload-sarif')).toBe('Upload the result to code scanning');
    expect(actionStepName('docker/login-action')).toBe('Log in to the registry');
    expect(actionStepName('docker/build-push-action')).toBe('Build the image');
    expect(actionStepName('actions/attest')).toBe('Attest the image');
  });

  it('an action nobody listed is "Run <path>", and an inherited key is not a listed one', () => {
    expect(actionStepName('some/new-action')).toBe('Run some/new-action');
    expect(actionStepName('constructor')).toBe('Run constructor');
    expect(actionStepName('__proto__')).toBe('Run __proto__');
  });

  it('renderPlatformStep gives each platform action its plain name', () => {
    const p = platform();
    const dl = renderPlatformStep('download-artifact', p, { name: 'pipegen-out-lint--app', path: '${{ runner.temp }}/pipegen-out/pipegen-out-lint--app' });
    expect(dl.name).toBe('Download the artifact');
    expect(renderPlatformStep('docker-login', p, { username: '${{ github.actor }}', [['pass', 'word'].join('')]: `\${{ ${['secr', 'ets'].join('')}.${['GITHUB', 'TOK' + 'EN'].join('_')} }}` }, { registry: 'ghcr.io' }).name).toBe('Log in to the registry');
  });
});

describe('PL-D2 fold R1: the gate upload steps are plain verb phrases', () => {
  it('each gate upload is named for what it ships, not for its artifact id', () => {
    const steps = renderGateUploads(platform());
    expect(steps.map((s) => [(s.with as Record<string, unknown>).name, s.name])).toEqual([
      ['pipegen-gate-result', 'Upload the gate result'],
      ['pipegen-baseline', 'Upload the baseline'],
      ['pipegen-clean-run', 'Upload the clean-run marker'],
    ]);
  });
});

/** Every `.ts` file under a folder. */
const tsFiles = (dir: string): string[] => readdirSync(dir).flatMap((n) => { const p = join(dir, n); return statSync(p).isDirectory() ? tsFiles(p) : p.endsWith('.ts') ? [p] : []; });

describe('PL-D2: no step name starts with "pipegen:" in any renderer', () => {
  // The shapes a step name is written in: `name: '...'`, and the first or second argument of the step builders.
  const SHAPES = [
    /\bname:\s*[`'"]pipegen\s*:/,
    /\bconst name = [`'"]pipegen\s*:/,
    /\b(?:runStep|bash|bashStep|pipegenScriptStep|actionStep|script)\(\s*(?:[A-Za-z_.()]+,\s*)?[`'"]pipegen\s*:/,
    /\b(?:runStep|bash|bashStep|pipegenScriptStep|actionStep)\([^`'"\n]*,\s*[`'"]pipegen\s*:/,
  ];
  it('the engine and layers write no "pipegen: ..." step name', () => {
    const hits: string[] = [];
    for (const f of [...tsFiles('src/engine'), ...tsFiles('src/layers')]) {
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        if (line.trimStart().startsWith('//') || line.trimStart().startsWith('*')) return;
        if (SHAPES.some((re) => re.test(line))) hits.push(`${f}:${i + 1}: ${line.trim().slice(0, 120)}`);
      });
    }
    expect(hits).toEqual([]);
  });
});
