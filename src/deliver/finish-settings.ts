// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import { gitBlobSha } from '../create/guard.js';
import { readShaPinning } from '../github/lock-probes.js';
import { GATE_RULESET, REVIEWS_RULESET, type ApiRequest } from '../layers/locks.js';
import type { InstallRecord } from '../types.js';
import { compareStatus, readTree, statusOf } from './git-data.js';
import { ACCESS_LEVELS } from './record.js';
import { classicPutForm, holdsWanted, isObj, refusedAsUnavailable } from './settings-api.js';
import { SHA_WHAT, show, StepError, type Ctx, isStop, whyOf, step, noteAbout, sameRuleset, keepPending, guardedWrite, apiCmd, appParams, centralParams } from './finish-base.js';
import { type Target, listRulesets, getRuleset, upsertRuleset, recordedRuleset, printRuleset } from './finish-rulesets.js';

// ---------- 1. the app's locks ----------

export async function appLocks(x: Ctx): Promise<void> {
  const P = x.planned;
  const F = x.fresh;
  if (P.rulesets === undefined && P.classic === undefined) return;
  const what = 'the merge locks (rulesets pipegen and pipegen-reviews)';
  if (F.rulesets === undefined) { x.skipped.push({ what, why: noteAbout(F, /lock merges|branch rules/) ?? 'GitHub no longer offers branch rules on this repo.' }); return; }
  const t: Target = { kind: 'repo', repo: x.app };
  let unavailable = P.rulesets === undefined;
  let existing: { id: number; name: string }[] = [];
  if (!unavailable) {
    try { existing = await listRulesets(x, t); } catch (e) {
      if (isStop(e)) throw e;
      if (refusedAsUnavailable(e)) unavailable = true;
      else { x.skipped.push({ what, why: whyOf(e) }); return; }
    }
  }
  const kinds: ['gate' | 'reviews', string, ApiRequest][] = [['gate', GATE_RULESET, F.rulesets.gate], ...(P.rulesets?.reviews === undefined ? [] : [['reviews', REVIEWS_RULESET, F.rulesets.reviews] as ['reviews', string, ApiRequest]])];
  if (!unavailable) {
    for (const [kind, name, req] of kinds) {
      if (x.print) { await printRuleset(x, t, name, req, existing); continue; }
      try {
        const r = await upsertRuleset(x, t, name, req.body, existing);
        x.applied.push(`ruleset ${name}${r.wrote === 'none' ? ' (already in place)' : ''}`);
        const prior = x.rec.rulesets.find((p) => p.kind === kind && p.id === r.id && sameRuleset(p.githubCreatedAt, r.createdAt));
        const entry = recordedRuleset(x, r, prior, `the ruleset ${name}`, `The ruleset ${name} that was already on ${show(`${x.app.owner}/${x.app.repo}`)}`);
        if (entry !== undefined) x.rulesets.set(kind, { kind, id: r.id, name: name as 'pipegen' | 'pipegen-reviews', ...entry });
      } catch (e) {
        if (isStop(e)) throw e;
        if (refusedAsUnavailable(e)) { unavailable = true; break; }
        x.skipped.push({ what: `ruleset ${name}`, why: whyOf(e) });
      }
    }
  }
  if (x.print && F.classic !== undefined && P.classic !== undefined) {
    x.commands.push('# Only if GitHub refuses the rulesets as not offered on this repo: classic branch protection instead (the same check and review rules)');
    x.commands.push(`# ${apiCmd(F.classic.method, F.classic.route, F.classic.params, F.classic.body).replace(/\n/g, '\n# ')}`);
  }
  if (unavailable && !x.print) await classic(x);
}

/** G8 carry: classic protection, only after GitHub refused rulesets as not offered. Its PUT-form body before is recorded once (null: none). */
export async function classic(x: Ctx): Promise<void> {
  const req = x.fresh.classic;
  const what = `classic branch protection on ${show(x.branch, 100)}`;
  if (req === undefined || x.planned.classic === undefined) { x.skipped.push({ what, why: 'GitHub doesn\'t offer rulesets on this repo, and no classic protection was planned.' }); return; }
  x.notes.push('GitHub doesn\'t offer rulesets on this repo, so pipegen uses classic branch protection instead: the same required check, bound to the same app, and the same review rules.');
  await step(x, what, async () => {
    const route = 'GET /repos/{owner}/{repo}/branches/{branch}/protection';
    const cur = await x.api.readOr404(route, req.params);
    const before = cur === null ? null : classicPutForm(cur);
    const prior = [x.rec.classicProtection, x.pending.classicProtection].find((c) => c?.branch === x.branch);
    if (before !== null && holdsWanted(req.body, before)) {
      x.applied.push(`${what} (already in place)`);
      if (prior !== undefined) x.classic = prior;
      else x.notes.push(`Classic branch protection on ${show(x.branch, 100)} was already as pipegen sets it, so pipegen can't tell what it was before and doesn't record it (uninstall leaves it as it is).`);
      return;
    }
    if (prior === undefined) await keepPending(x, (p) => { p.classicProtection = { branch: x.branch, previous: before }; });
    await guardedWrite(x, prior === undefined ? (p) => { delete p.classicProtection; } : undefined, () => x.api.write(`${req.method} ${req.route}`, { ...req.params, ...req.body }));
    const back = await x.api.readOr404(route, req.params);
    if (back === null || !holdsWanted(req.body, classicPutForm(back))) throw new StepError(`Classic branch protection on ${show(x.branch, 100)} doesn't read back as pipegen set it.`);
    x.classic = prior ?? { branch: x.branch, previous: before };
    x.applied.push(what);
  });
}

// ---------- 2. repo settings ----------

export async function shaPinning(x: Ctx): Promise<void> {
  if (x.planned.shaPinning === undefined) return;
  const F = x.fresh.shaPinning;
  if (F === undefined || x.shaRead.state !== 'read') { x.skipped.push({ what: SHA_WHAT, why: noteAbout(x.fresh, /full-length commit SHA/) ?? 'GitHub doesn\'t offer the setting on this repo now.' }); return; }
  const prior = x.rec.repoSettings?.shaPinningRequired ?? x.pending.repoSettings.shaPinningRequired;
  if (x.shaRead.required) {
    if (prior !== undefined) x.repoSettings.shaPinningRequired = prior;
    x.applied.push(`${SHA_WHAT} (already on)`);
    return;
  }
  if (x.print) { x.commands.push(apiCmd(F.request.method, F.request.route, F.request.params, F.request.body)); return; }
  await step(x, SHA_WHAT, async () => {
    if (prior === undefined) await keepPending(x, (p) => { p.repoSettings.shaPinningRequired = { previous: false }; });
    await guardedWrite(x, prior === undefined ? (p) => { delete p.repoSettings.shaPinningRequired; } : undefined, () => x.api.write(`${F.request.method} ${F.request.route}`, { ...F.request.params, ...F.request.body }));
    const back = await readShaPinning(x.gh, x.app.owner, x.app.repo, [], x.clock);
    if (back.state !== 'read' || back.required !== true) throw new StepError('The setting doesn\'t read back as on.');
    x.repoSettings.shaPinningRequired = prior ?? { previous: false };
    x.applied.push(SHA_WHAT);
  });
}

export async function securitySettings(x: Ctx): Promise<void> {
  const p = appParams(x);
  const alertsOn = async (): Promise<boolean> => {
    try { return (await x.api.read('GET /repos/{owner}/{repo}/vulnerability-alerts', p)).status === 204; } catch (e) {
      if (statusOf(e) === 404) return false;
      throw e;
    }
  };
  const what = 'Dependabot alerts';
  await step(x, what, async () => {
    const prior = x.rec.repoSettings?.vulnerabilityAlerts ?? x.pending.repoSettings.vulnerabilityAlerts;
    if (await alertsOn()) {
      if (prior !== undefined) x.repoSettings.vulnerabilityAlerts = prior;
      x.applied.push(`${what} (already on)`);
      return;
    }
    if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/vulnerability-alerts', p)); return; }
    if (prior === undefined) await keepPending(x, (q) => { q.repoSettings.vulnerabilityAlerts = { previous: false }; });
    await guardedWrite(x, prior === undefined ? (q) => { delete q.repoSettings.vulnerabilityAlerts; } : undefined, () => x.api.write('PUT /repos/{owner}/{repo}/vulnerability-alerts', p));
    if (!await alertsOn()) throw new StepError('Dependabot alerts don\'t read back as on.');
    x.repoSettings.vulnerabilityAlerts = prior ?? { previous: false };
    x.applied.push(what);
  });
  if (x.private) {
    x.notes.push('Secret scanning and push protection on a private repo come with GitHub\'s paid Secret Protection add-on, so pipegen leaves them as they are; turn them on in the repository settings if you have the add-on.');
    return;
  }
  const what2 = 'secret scanning and push protection';
  await step(x, what2, async () => {
    const read = async (): Promise<{ ss: boolean; pp: boolean }> => {
      const d = (await x.api.read('GET /repos/{owner}/{repo}', p)).data;
      const sa = isObj(d) && isObj(d.security_and_analysis) ? d.security_and_analysis : {};
      const on = (k: string): boolean => isObj(sa[k]) && (sa[k] as { status?: unknown }).status === 'enabled';
      return { ss: on('secret_scanning'), pp: on('secret_scanning_push_protection') };
    };
    const cur = await read();
    const prior = { ss: x.rec.repoSettings?.secretScanning ?? x.pending.repoSettings.secretScanning, pp: x.rec.repoSettings?.pushProtection ?? x.pending.repoSettings.pushProtection };
    const keep = (): void => {
      if (prior.ss !== undefined) x.repoSettings.secretScanning = prior.ss;
      if (prior.pp !== undefined) x.repoSettings.pushProtection = prior.pp;
    };
    if (cur.ss && cur.pp) { keep(); x.applied.push(`${what2} (already on)`); return; }
    const body = { security_and_analysis: { secret_scanning: { status: 'enabled' }, secret_scanning_push_protection: { status: 'enabled' } } };
    if (x.print) { x.commands.push(apiCmd('PATCH', '/repos/{owner}/{repo}', p, body)); return; }
    const add: NonNullable<InstallRecord['repoSettings']> = { ...(prior.ss === undefined && !cur.ss ? { secretScanning: { previous: false } } : {}), ...(prior.pp === undefined && !cur.pp ? { pushProtection: { previous: false } } : {}) };
    if (Object.keys(add).length > 0) await keepPending(x, (q) => { Object.assign(q.repoSettings, add); });
    await guardedWrite(x, Object.keys(add).length > 0 ? (q) => { for (const k of Object.keys(add) as (keyof typeof add)[]) delete q.repoSettings[k]; } : undefined, () => x.api.write('PATCH /repos/{owner}/{repo}', { ...p, ...body }));
    const back = await read();
    if (!back.ss || !back.pp) throw new StepError('Secret scanning and push protection don\'t read back as on.');
    keep();
    Object.assign(x.repoSettings, add);
    x.applied.push(what2);
  });
}

/** The central repo's Actions access (private apps: the app's workflows call the central ones). Its earlier level recorded once. */
export async function actionsAccess(x: Ctx): Promise<void> {
  if (!x.private) return;
  const level = x.ownerType === 'Organization' ? 'organization' : 'user';
  const what = `the Actions access of ${show(`${x.central.owner}/${x.central.repo}`)} (${level})`;
  const p = centralParams(x);
  await step(x, what, async () => {
    const read = async (): Promise<string | null> => {
      const d = (await x.api.read('GET /repos/{owner}/{repo}/actions/permissions/access', p)).data;
      return isObj(d) && typeof d.access_level === 'string' ? d.access_level : null;
    };
    const cur = await read();
    const prior = x.rec.central?.actionsAccess ?? x.pending.actionsAccess;
    if (cur === level || (level === 'organization' && cur === 'enterprise')) {
      if (prior !== undefined) x.centralRec.actionsAccess = prior;
      x.applied.push(`${what} (already set)`);
      return;
    }
    if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/actions/permissions/access', p, { access_level: level })); return; }
    // V9a-R2: only a level GitHub names is recorded (the record schema takes no other; uninstall prints it in a step)
    const prev = prior ?? (cur !== null && (ACCESS_LEVELS as readonly string[]).includes(cur) ? { previous: cur } : undefined);
    if (prior === undefined && prev !== undefined) await keepPending(x, (q) => { q.actionsAccess = prev; });
    await guardedWrite(x, prior === undefined && prev !== undefined ? (q) => { delete q.actionsAccess; } : undefined, () => x.api.write('PUT /repos/{owner}/{repo}/actions/permissions/access', { ...p, access_level: level }));
    if (await read() !== level) throw new StepError('The access level doesn\'t read back as set.');
    if (prev !== undefined) x.centralRec.actionsAccess = prev;
    x.applied.push(what);
  });
}

// ---------- 3. the org required workflow ----------

export async function orgRequired(x: Ctx): Promise<void> {
  if (x.planned.orgRequiredWorkflow === undefined) return;
  const what = 'the org required workflow';
  const F = x.fresh.orgRequiredWorkflow;
  if (F === undefined) { x.skipped.push({ what, why: noteAbout(x.fresh, /org required workflow/) ?? 'It can\'t be planned on this repo now.' }); return; }
  // G10-R1: the rule runs the file at the commit it names; the file exists only from the record's commit on (it calls the pinned one)
  const e = x.centralTree.get(F.file.path);
  if (e === undefined || e.type !== 'blob' || e.mode !== '100644' || e.sha !== gitBlobSha(F.file.content)) {
    x.skipped.push({ what, why: `The central default branch of ${show(`${x.central.owner}/${x.central.repo}`)} doesn't hold ${show(F.file.path)} as pipegen wrote it, so pipegen adds no rule that would run it. If the central pull request pipegen opened is still open, merge it, then run \`npx pipegen finish\` again; otherwise run pipegen again to deliver it.` });
    return;
  }
  const body = structuredClone(F.rule.body);
  const rules = Array.isArray(body.rules) ? body.rules : [];
  const wf = (rules[0] as { parameters?: { workflows?: Record<string, unknown>[] } } | undefined)?.parameters?.workflows?.[0];
  if (wf === undefined || wf.path !== F.file.path) { x.skipped.push({ what, why: 'The planned rule doesn\'t name the required workflow.' }); return; }
  const name = String(body.name);
  const t: Target = { kind: 'org', org: x.app.owner };
  let pin = x.centralHead;
  await step(x, `${what} (ruleset ${show(name, 100)})`, async () => {
    const existing = await listRulesets(x, t);
    // G17 row 41 (G11 R2-3): the record commit moves the central head on every run, so a re-run keeps the live pin while it still holds
    // pipegen's required workflow (a commit on the central default branch whose file is the one planned now); anything else: the head
    pin = await keptPin(x, t, name, existing, F.file.path, gitBlobSha(F.file.content)) ?? x.centralHead;
    wf.sha = pin;
    if (x.print) { await printRuleset(x, t, name, { ...F.rule, body }, existing); return; }
    const r = await upsertRuleset(x, t, name, body, existing);
    const p = x.rec.orgRuleset;
    const prior = p !== undefined && p.id === r.id && sameRuleset(p.githubCreatedAt, r.createdAt) ? p : undefined;
    const entry = recordedRuleset(x, r, prior, `the org ruleset ${show(name, 100)}`, `The org ruleset ${show(name, 100)} that was already there`);
    // G11-R-sec1: the commit the rule's workflow entry is pinned to (read back above), so verify can hold the live rule to it
    if (entry !== undefined) x.orgRuleset = { org: x.app.owner, id: r.id, name, ...entry, pinnedSha: pin };
    x.applied.push(`${what} (ruleset ${show(name, 100)}, pinned to ${pin.slice(0, 12)})${r.wrote === 'none' ? ' (already in place)' : ''}`);
  });
}

/**
 * G17 row 41: the commit the live same-name org rule pins, when finish may keep it: one workflow entry, at `path`, naming a full sha that is on
 * the central default branch (compare: identical or behind) and holds `path` as the blob `blob` (pipegen's required workflow as planned now).
 * Anything else, or anything GitHub doesn't show: null (finish pins the central head).
 */
export async function keptPin(x: Ctx, t: Target, name: string, existing: readonly { id: number; name: string }[], path: string, blob: string): Promise<string | null> {
  const same = existing.filter((r) => r.name === name);
  if (same.length !== 1 || same[0] === undefined) return null;
  const cur = await getRuleset(x, t, same[0].id);
  const rules = cur !== null && Array.isArray(cur.rules) ? cur.rules.filter(isObj) : [];
  const wfs = rules.flatMap((r) => (isObj(r.parameters) && Array.isArray(r.parameters.workflows) ? r.parameters.workflows : [null]));
  const only = wfs.length === 1 && isObj(wfs[0]) ? wfs[0] : null;
  const sha = only?.sha;
  if (only === null || only.path !== path || typeof sha !== 'string' || !/^[0-9a-f]{40}$/.test(sha)) return null;
  if (sha === x.centralHead) return sha;
  try {
    const status = await compareStatus(x.gh, x.central, x.centralBranch, sha, x.clock);
    if (status !== 'identical' && status !== 'behind') return null;
    const e = (await readTree(x.gh, x.central, sha, x.clock)).entries.get(path);
    return e !== undefined && e.type === 'blob' && e.mode === '100644' && e.sha === blob ? sha : null;
  } catch (e) {
    if (isStop(e)) throw e;
    return null;
  }
}
