// PL-E1: split out of finish.ts (a pure move, by step); see finish.ts for the whole story.
import { COSIGN_KEY_SECRET, storeCosignKey, storeEnvSecret } from '../create/secrets.js';
import { SIGNING_ENVIRONMENT } from '../engine/referee.js';
import { pubKeySha256 } from '../engine/signing.js';
import { signingMode } from '../github/signing-mode.js';
import { type EnvSettings } from '../types.js';
import { generateCosignKeys } from '../layers/deploy.js';
import { ensureSigningEnvironment, readEnv } from './deliver.js';
import { isoAt } from './git-data.js';
import { type FinishPending } from './record.js';
import { isObj } from './settings-api.js';
import { COSIGN_PUB_VAR, PASSWORD_SECRET, SIGNING_SCOPE, show, StepError, type EnvEntry, type VarEntry, type Ctx, isStop, whyOf, step, sameInstant, priorOf, atOf, keepPending, keepMade, guardedWrite, pendEnv, pendVar, apiCmd, appParams } from './finish-base.js';

// ---------- 4. environments ----------

export async function environments(x: Ctx): Promise<void> {
  for (const e of x.planned.environments) {
    if (e.name === SIGNING_ENVIRONMENT) continue;
    const what = `environment ${show(e.name, 100)}`;
    if (!x.caps.environments) { x.skipped.push({ what, why: 'GitHub no longer offers environments on this repo (its plan), so pipegen leaves it.' }); continue; }
    await step(x, what, async () => {
      const ids: { type: 'User'; id: number }[] = [];
      if (e.reviewers) {
        if (!x.caps.envRequiredReviewers) x.notes.push(`GitHub doesn't offer required reviewers on this repo's environments, so ${what} gets none.`);
        else if (x.fresh.owners.app.length === 0) x.notes.push(`No code owners review changes here, so ${what} gets no required reviewers: nobody else could approve a deploy.`);
        else {
          for (const login of x.fresh.owners.app.slice(0, 6)) {
            const d = (await x.api.read('GET /users/{username}', { username: login.slice(1) })).data;
            if (!isObj(d) || !Number.isSafeInteger(d.id) || (d.id as number) <= 0) throw new StepError(`GitHub's answer about ${show(login, 40)} could not be read.`);
            ids.push({ type: 'User', id: d.id as number });
          }
        }
      }
      const cur = await readEnv(x.gh, x.app, x.clock, e.name);
      const s = cur?.settings;
      const want: Omit<EnvSettings, 'branch_policies'> = {
        wait_timer: s?.wait_timer ?? 0, prevent_self_review: ids.length > 0 ? true : s?.prevent_self_review ?? false, reviewers: ids.length > 0 ? ids : s?.reviewers ?? [],
        can_admins_bypass: s?.can_admins_bypass ?? true, deployment_branch_policy: s?.deployment_branch_policy ?? null,
      };
      const keys = Object.keys(want) as (keyof typeof want)[];
      const changed = cur === null ? [] : keys.filter((k) => JSON.stringify(want[k]) !== JSON.stringify(s?.[k]));
      // captured once: an earlier entry for this environment (the record's, else one an earlier run saved before it stopped, I1), adopted
      // only when it is the same object; a maybe-same one gives only its previous value (G11-R2 d)
      // G11-R3 (R2-4): an ISO-Z created_at, else unknown (as setVariable reads it): an empty or offset one never hides the earlier entry
      const curAt = cur !== null && isoAt(cur.createdAt) ? cur.createdAt : null;
      const m = cur === null ? undefined : priorOf([x.rec.environments, x.pending.environments], (p) => p.name === e.name, curAt);
      const prior = m?.kind === 'same' ? m.entry : undefined;
      const kept = m?.kind === 'maybe' ? m.entry : undefined;
      let back = cur;
      if (cur === null || changed.length > 0) {
        const params = { ...appParams(x), environment_name: e.name };
        if (x.print) { x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/environments/{environment_name}', params, { ...want })); return; }
        const saving = cur !== null && prior === undefined && kept === undefined;
        if (saving) {
          const was: EnvEntry = { name: e.name, created: false, ...atOf(curAt), previous: { ...cur.settings, branch_policies: cur.policies.map((p) => ({ name: p.name, type: p.type })) }, changed, branchPolicyIds: [] };
          await keepPending(x, (q) => pendEnv(q, was));
        }
        await guardedWrite(x, saving ? (q) => { q.environments = q.environments.filter((v) => v.name !== e.name); } : undefined, () => x.api.write('PUT /repos/{owner}/{repo}/environments/{environment_name}', { ...params, ...want }));
        back = await readEnv(x.gh, x.app, x.clock, e.name);
        if (back === null || keys.some((k) => JSON.stringify(back?.settings[k]) !== JSON.stringify(want[k]))) throw new StepError(`The environment ${show(e.name, 100)} doesn't read back as pipegen set it.`);
      }
      if (x.print) return;
      const atField = atOf(back?.createdAt ?? null);
      let entry: EnvEntry;
      if (prior !== undefined) entry = { ...prior, changed: [...new Set([...prior.changed, ...changed])] };
      else if (kept !== undefined) entry = { name: e.name, created: false, ...atOf(curAt), previous: kept.previous as EnvSettings, changed: [...new Set([...kept.changed, ...changed])], branchPolicyIds: [] };
      else if (cur === null) {
        entry = { name: e.name, created: true, ...atField, changed: [], branchPolicyIds: [] };
        if ('githubCreatedAt' in atField) await keepMade(x, (q) => pendEnv(q, entry));
      } else if (changed.length > 0) entry = { name: e.name, created: false, ...atOf(curAt), previous: { ...cur.settings, branch_policies: cur.policies.map((p) => ({ name: p.name, type: p.type })) }, changed, branchPolicyIds: [] };
      else entry = { name: e.name, created: false, ...atField, changed: [], branchPolicyIds: [] };
      x.environments.set(e.name, entry);
      x.applied.push(`${what}${cur !== null && changed.length === 0 ? ' (already in place)' : ''}`);
    });
  }
}

// ---------- 5. signing ----------

export async function secretAt(x: Ctx, name: string): Promise<string | null> {
  const d = await x.api.readOr404('GET /repos/{owner}/{repo}/environments/{environment_name}/secrets/{secret_name}', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT, secret_name: name });
  if (d === null) return null;
  return isObj(d) && typeof d.created_at === 'string' ? d.created_at : '';
}

/** A repo or environment variable set to `value` (created, or changed from what it was), read back; its record entry kept once. */
export async function setVariable(x: Ctx, scope: 'repo' | `env:${string}`, name: string, value: string, what: string): Promise<void> {
  const env = scope === 'repo' ? null : scope.slice(4);
  const p = { ...appParams(x), ...(env === null ? {} : { environment_name: env }) };
  const one = env === null ? '/repos/{owner}/{repo}/actions/variables/{name}' : '/repos/{owner}/{repo}/environments/{environment_name}/variables/{name}';
  const all = env === null ? '/repos/{owner}/{repo}/actions/variables' : '/repos/{owner}/{repo}/environments/{environment_name}/variables';
  const read = async (): Promise<{ value: string; createdAt: string | null } | null> => {
    const d = await x.api.readOr404(`GET ${one}`, { ...p, name });
    if (d === null) return null;
    if (!isObj(d) || typeof d.value !== 'string') throw new StepError(`GitHub's answer about ${name} could not be read.`);
    return { value: d.value, createdAt: isoAt(d.created_at) ? d.created_at : null };
  };
  const cur = await read();
  if (cur !== null && cur.value !== value && cur.value.length > 10_000) throw new StepError(`${name} holds a value too long for pipegen to keep for uninstall, so pipegen leaves it; remove it, then run finish again.`);
  if (x.print) {
    if (cur?.value === value) { x.commands.push(`# ${name} is already set`); return; }
    x.commands.push(env === null ? `gh variable set ${name} --repo ${x.app.owner}/${x.app.repo} --body ${value}` : `gh variable set ${name} --env ${env} --repo ${x.app.owner}/${x.app.repo} --body '${value}'`);
    return;
  }
  // captured once: never pipegen's own value as previous (the record's entry, else one an earlier run saved before it stopped, I1; m3)
  // adopted only when it is the same object; a maybe-same one gives only its previous value (G11-R2 d)
  const m = cur === null ? undefined : priorOf([x.rec.variables, x.pending.variables], (v) => v.name === name && v.scope === scope, cur.createdAt);
  const prior = m?.kind === 'same' ? m.entry : undefined;
  const kept = m?.kind === 'maybe' ? m.entry : undefined;
  const saving = cur !== null && cur.value !== value && prior === undefined && kept === undefined;
  if (saving) await keepPending(x, (q) => pendVar(q, { name, scope, created: false, previous: cur.value, ...atOf(cur.createdAt) }));
  const unsave = saving ? (q: FinishPending): void => { q.variables = q.variables.filter((v) => !(v.name === name && v.scope === scope)); } : undefined;
  if (cur === null) await x.api.write(`POST ${all}`, { ...p, name, value });
  else if (cur.value !== value) await guardedWrite(x, unsave, () => x.api.write(`PATCH ${one}`, { ...p, name, value }));
  const back = await read();
  if (back === null || back.value !== value) throw new StepError(`${name} doesn't read back as pipegen set it.`);
  const at = atOf(back.createdAt);
  let entry: VarEntry;
  if (prior !== undefined) entry = { ...prior };
  else if (kept !== undefined && cur !== null) entry = { name, scope, created: false, previous: kept.previous as string, ...atOf(cur.createdAt) };
  else if (cur === null) {
    entry = { name, scope, created: true, ...at };
    if ('githubCreatedAt' in at) await keepMade(x, (q) => pendVar(q, entry));
  } else if (cur.value !== value) entry = { name, scope, created: false, previous: cur.value, ...atOf(cur.createdAt) };
  else entry = { name, scope, created: false, ...at };
  x.variables = [...x.variables.filter((v) => !(v.name === name && v.scope === scope)), entry];
  x.applied.push(cur?.value === value ? `${what} (already set)` : what);
}

export async function signing(x: Ctx): Promise<void> {
  if (x.planned.signingMode !== 'key-env') return;
  const whatEnv = `the signing environment ${SIGNING_ENVIRONMENT} (default branch only)`;
  const whatKey = `the signing key (${COSIGN_KEY_SECRET}, ${PASSWORD_SECRET})`;
  const whatPub = `${COSIGN_PUB_VAR} (environment ${SIGNING_ENVIRONMENT})`;
  if (!x.caps.environments) { x.skipped.push({ what: whatEnv, why: 'GitHub no longer offers environments on this repo, so pipegen keeps no signing key there: signing is off (mode none).' }); return; }
  const needKey = x.rotate || !x.rec.secrets.some((s) => s.scope === SIGNING_SCOPE && s.name === COSIGN_KEY_SECRET);
  const repo = `${x.app.owner}/${x.app.repo}`;
  const noPub = (): { what: string; why: string } => ({ what: whatPub, why: `pipegen couldn't re-derive the public key from the install record (${x.typed ? 'a record confirmed by typing doesn\'t carry it' : 'it holds none'}), so it sets no ${COSIGN_PUB_VAR}; run \`npx pipegen finish --rotate-key\` to make a new key pair.` });
  if (x.print) {
    // m8: an environment GitHub won't show is reported by name, like every other step
    let env: Awaited<ReturnType<typeof readEnv>> = null;
    if (!await step(x, whatEnv, async () => { env = await readEnv(x.gh, x.app, x.clock); })) return;
    const e = env as Awaited<ReturnType<typeof readEnv>>;
    const ok = e !== null && e.settings.deployment_branch_policy?.protected_branches === false && e.settings.deployment_branch_policy.custom_branch_policies === true && e.policies.length === 1 && e.policies[0]?.name === x.branch && e.policies[0].type === 'branch';
    if (!ok) {
      x.commands.push(`# The environment ${SIGNING_ENVIRONMENT}, usable from the default branch only (check it reads back so before you store a key in it)`);
      x.commands.push(apiCmd('PUT', '/repos/{owner}/{repo}/environments/{environment_name}', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT }, { deployment_branch_policy: { protected_branches: false, custom_branch_policies: true } }));
      x.commands.push(apiCmd('POST', '/repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies', { ...appParams(x), environment_name: SIGNING_ENVIRONMENT }, { name: x.branch, type: 'branch' }));
    }
    if (needKey) {
      // G17 row 45 (G13 sec M5): the key pair is made in a memory folder, never the clone (where it could be committed), and its password
      // goes through COSIGN_PASSWORD (cosign reads it there), never a file or a command line. G17-R4 (sec C1): one subshell block that the
      // first failure ends (a missing /dev/shm, cosign or gh), so no key is made outside the folder and nothing is stored after a failure;
      // the folder is a variable its trap removes (never "$OLDPWD"), and the password and umask end with the subshell
      x.commands.push('# A new key pair, made in a fresh memory folder (/dev/shm: never your clone, where the key could be committed). Paste the whole block into a POSIX shell (sh, bash or zsh; from fish or csh, start sh first). It stops at the first failure and then stores nothing more; the folder, the random password (only in COSIGN_PASSWORD, never a file) and the umask end with it. If it stopped after a gh line, run the whole block again: a half-stored pair cannot sign. Without a memory /dev/shm (macOS, Windows Git Bash, where /dev/shm is on disk) it stops before making a key: run npx pipegen finish --rotate-key on a Linux host instead.');
      x.commands.push([
        '(',
        '  set -eu +x',
        '  umask 077',
        '  d="$(mktemp -d -p /dev/shm)"',
        '  trap \'rm -rf -- "$d"\' EXIT',
        '  trap \'exit 130\' HUP INT TERM',
        '  test -d "$d"',
        '  case "$(stat -f -c %T "$d")" in tmpfs|ramfs) ;; *) exit 1 ;; esac',
        '  cd "$d"',
        '  COSIGN_PASSWORD="$(head -c 32 /dev/urandom | base64 | tr -d \'\\n\')"; export COSIGN_PASSWORD',
        '  test "${#COSIGN_PASSWORD}" -eq 44',
        '  cosign generate-key-pair --output-key-prefix pipegen-signing',
        `  gh secret set ${COSIGN_KEY_SECRET} --env ${SIGNING_ENVIRONMENT} --repo ${repo} < pipegen-signing.key`,
        `  printf '%s' "$COSIGN_PASSWORD" | gh secret set ${PASSWORD_SECRET} --env ${SIGNING_ENVIRONMENT} --repo ${repo}`,
        `  gh variable set ${COSIGN_PUB_VAR} --env ${SIGNING_ENVIRONMENT} --repo ${repo} < pipegen-signing.pub`,
        ')',
      ].join('\n'));
      x.commands.push('# The verify step checks the new public key\'s sha256 only after a pull request puts it in your workflow (run npx pipegen run again).');
    } else if (x.rec.cosignPub !== undefined) await step(x, whatPub, () => setVariable(x, SIGNING_SCOPE, COSIGN_PUB_VAR, x.rec.cosignPub as string, whatPub));
    else x.skipped.push(noPub());
    return;
  }
  // S-7: the environment and its default-branch rule, read back, before any key
  let env: EnvEntry;
  try { env = await ensureSigningEnvironment(x.gh, x.app, x.branch, x.rec.environments.find((e) => e.name === SIGNING_ENVIRONMENT), x.clock, x.notes); } catch (e) {
    if (isStop(e)) throw e;
    x.skipped.push({ what: whatKey, why: `${whyOf(e)} pipegen stores no signing key and sets no ${COSIGN_PUB_VAR}: signing is off (mode none) until it does.` });
    x.notes.push(`Signing is off (mode none): the environment ${SIGNING_ENVIRONMENT} didn't read back as usable from the default branch only. Fix it in the repository settings, then run \`npx pipegen finish\` again.`);
    return;
  }
  x.environments.set(SIGNING_ENVIRONMENT, env);
  x.applied.push(whatEnv);
  if (signingMode(x.profile, { ...x.caps, deploymentBranchPolicies: true }) !== 'key-env') {
    x.skipped.push({ what: whatKey, why: 'GitHub doesn\'t offer what key-env signing needs on this repo now, so pipegen stores no key: signing is off (mode none).' });
    return;
  }
  let pub: string;
  if (needKey) {
    let made = false;
    let fresh = '';
    await step(x, whatKey, async () => {
      // G13 (carry 28): only in a memory folder (generateCosignKeys refuses any other, before cosign runs)
      const keys = await generateCosignKeys(x.deps.cosignBin, {
        ...(x.deps.exec === undefined ? {} : { exec: x.deps.exec }), ...(x.deps.keyBase === undefined ? {} : { base: x.deps.keyBase }),
        ...(x.deps.isMemory === undefined ? {} : { isMemory: x.deps.isMemory }),
      });
      const pair = { key: keys.privateKey, password: keys.password, pub: keys.publicKey };
      const stores: [string, () => Promise<void>][] = [
        [COSIGN_KEY_SECRET, () => storeCosignKey(x.gh, x.app, SIGNING_ENVIRONMENT, pair.key, x.clock)],
        [PASSWORD_SECRET, () => storeEnvSecret(x.gh, x.app, SIGNING_ENVIRONMENT, PASSWORD_SECRET, pair.password, x.clock)],
      ];
      // deliver stored none (S11): an existing secret of the same name is not pipegen's to replace without --rotate-key
      if (!x.rotate) for (const [name] of stores) if (await secretAt(x, name) !== null) throw new StepError(`${SIGNING_ENVIRONMENT} already has ${name}, which no install record shows pipegen stored; run \`npx pipegen finish --rotate-key\` to replace the key pair.`);
      for (const [i, [name, store]] of stores.entries()) {
        const before = await secretAt(x, name);
        try { await store(); } catch (e) {
          if (i === 0) throw e;
          // m2: the new private key is stored, its password is not: the pair no longer matches, so nothing can be signed
          x.halfKey = true;
          if (isStop(e)) throw e;
          throw new StepError(`pipegen stored the new ${COSIGN_KEY_SECRET} but couldn't store ${name} (${whyOf(e)}). The key and its password no longer match, so signing is broken until you run \`npx pipegen finish --rotate-key\` again to store a new pair.`);
        }
        const after = await secretAt(x, name).catch((e: unknown) => { if (isStop(e)) throw e; return null; });
        const at = after !== null && isoAt(after) ? { githubCreatedAt: after } : { unconfirmed: true as const };
        const prior = x.rec.secrets.find((s) => s.name === name && s.scope === SIGNING_SCOPE);
        const own = before !== null && prior?.created === true && prior.githubCreatedAt !== undefined && sameInstant(prior.githubCreatedAt, before);   // G17 row 43: as instants
        x.secrets.push(before === null || own ? { name, scope: SIGNING_SCOPE, created: true, ...at } : { name, scope: SIGNING_SCOPE, created: false, overwritten: true, ...at });
      }
      fresh = pair.pub;
      made = true;
    });
    if (!made) return;
    pub = fresh;
    x.applied.push(whatKey);
    x.notes.push('The new signing key replaces the old one: images signed with the old key won\'t verify any more. Re-run the pipeline on the commit you deploy to sign it again with the new key.');
    x.notes.push('The verify step fails closed until a pull request puts the new public key\'s sha256 in your workflow: that literal changes only through a pull request (run `npx pipegen run` again to open it).');
    x.newKey = true;
  } else {
    const p = x.rec.cosignPub;
    if (p === undefined || x.rec.cosignPubSha256 === undefined || pubKeySha256(p) !== x.rec.cosignPubSha256) {
      x.skipped.push(noPub());
      return;
    }
    const missing: string[] = [];
    for (const name of [COSIGN_KEY_SECRET, PASSWORD_SECRET]) if (await secretAt(x, name) === null) missing.push(name);
    if (missing.length > 0) x.skipped.push({ what: whatKey, why: `${missing.join(' and ')} ${missing.length === 1 ? 'is' : 'are'} missing from ${SIGNING_ENVIRONMENT}, so nothing can be signed; run \`npx pipegen finish --rotate-key\` to make a new key pair.` });
    pub = p;
  }
  if (await step(x, whatPub, () => setVariable(x, SIGNING_SCOPE, COSIGN_PUB_VAR, pub, whatPub))) x.cosign = { pub, sha: pubKeySha256(pub) };
  else if (needKey) x.cosign = { pub, sha: pubKeySha256(pub) };   // the key pair is stored: the record names its public key, so verify reports the variable
}
