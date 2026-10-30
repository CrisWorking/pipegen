// Shared by the live tests of the secrets tools (C1b fix rounds): run the reviewed entry's own command with the pinned binaries.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CANARY_RULE_TOML } from '../../src/ai/scan-staging.js';
import { loadReviewed } from '../../src/engine/reviewed.js';
import { makeTempDir, writeIn } from './make-repo.js';

export const git = (dir: string, ...args: string[]): void => {
  execFileSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', ...args], { cwd: dir, stdio: 'pipe' });
};

/** The reviewed entry's own command, with the pinned config and an absolute report path; returns the SARIF text. */
export function runEntry(id: 'betterleaks' | 'gitleaks', bin: string, dir: string): string {
  const entry = loadReviewed().find((t) => t.id === id);
  if (entry?.step.cli === undefined) throw new Error('no entry');
  const report = join(makeTempDir(), `${id}.sarif`);
  const conf = join(makeTempDir(), `${id}.toml`);
  writeIn(join(conf, '..'), `${id}.toml`, entry.fixedInputs.config?.content ?? '');
  const argv = entry.step.cli.command.slice(1).map((a) => (a === `${id}.sarif` ? report : a));
  try {
    execFileSync(bin, [...argv.slice(0, -1), '--config', conf, argv.at(-1) as string], { cwd: dir, stdio: 'pipe', env: { PATH: process.env.PATH ?? '', HOME: dir }, timeout: 120_000 });
  } catch (e) {
    if ((e as { status?: number }).status !== 10) throw e;
  }
  return readFileSync(report, 'utf8');
}


/** C1c: the pinned config with pipegen's canary rule, as the staged secrets scan runs it. */
export const STAGED_CONFIG = `[extend]\nuseDefault = true\n\n${CANARY_RULE_TOML}`;

/**
 * C1c: the reviewed entry's command on a stage folder, as the rendered step runs it: cwd = the staged files folder (the ignore-file
 * lookup uses the cwd), scanning `.`, the report written outside the folder, the config with the canary rule. Returns the SARIF text.
 */
export function runStaged(id: 'betterleaks' | 'gitleaks', bin: string, stage: string, config = STAGED_CONFIG): string {
  const entry = loadReviewed().find((t) => t.id === id);
  if (entry?.step.cli === undefined) throw new Error('no entry');
  const report = join(makeTempDir(), `${id}.sarif`);
  const conf = join(makeTempDir(), `${id}.toml`);
  writeIn(join(conf, '..'), `${id}.toml`, config);
  const argv = entry.step.cli.command.slice(1).map((a) => (a === `${id}.sarif` ? report : a));
  try {
    execFileSync(bin, [...argv.slice(0, -1), '--config', conf, argv.at(-1) as string], { cwd: join(stage, 'files'), stdio: 'pipe', env: { PATH: process.env.PATH ?? '', HOME: makeTempDir() }, timeout: 300_000 });
  } catch (e) {
    if ((e as { status?: number }).status !== 10) throw e;
  }
  return readFileSync(report, 'utf8');
}
