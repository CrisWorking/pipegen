// pipegen's never-list (catalogue §4 "Remove / never add"), in one leaf module (no imports) so every rule that reads it
// uses the same list: the reviewed-list loader, discovery and the chooser (reviewed.ts re-exports it), and the audit's
// coverage mapper (Plan P ruling P33: a step that uses a never-listed action never makes a check "covered"). J3b (ruling
// S6): the coverage mapper alone judges a step pinned to a checked commit SHA by that SHA (NEVER_SAFE_SHAS,
// neverListedStep); everything pipegen adds still goes through neverListed, which refuses the name at any ref.

const lower = (s: string) => s.toLowerCase();
/**
 * Catalogue §4's never-list ("Remove / never add"), lowercased `owner/name` (or `owner/*` for every repo of an owner)
 * → why. It also holds the old names GitHub still redirects to these repos (checked with the GitHub API on
 * 2026-10-27) and the same projects' own action repos. neverListed matches it.
 */
export const NEVER_REPOS: Readonly<Record<string, string>> = Object.freeze({
  'checkmarx/kics-github-action': 'KICS: its action tags were hijacked in 2026 (catalogue §4, §5)',
  'checkmarx/kics-action': 'KICS: the old name of checkmarx/kics-github-action, whose tags were hijacked in 2026 (catalogue §4, §5)',
  'checkmarx/kics': 'KICS: its Docker Hub tags were overwritten with a data-stealing binary in 2026 (catalogue §4, §5)',
  'aquasecurity/trivy-action': '76 of its 77 tags were force-pushed to malicious code in March 2026; Trivy runs only as the verified binary (catalogue §4, §5)',
  'aquasecurity/setup-trivy': 'all its tags were replaced with malicious code in March 2026; Trivy runs only as the verified binary (catalogue §4, §5)',
  'gitleaks/gitleaks-action': 'proprietary licence, needs a licence key and phones home (catalogue §4)',
  'zricethezav/gitleaks-action': 'the old name of gitleaks/gitleaks-action: proprietary licence, licence key, phones home (catalogue §4)',
  'reviewdog/*': 'reviewdog actions: reviewdog/action-setup was hijacked (CVE-2025-30154); pipegen uses plain run steps (catalogue §4, §5)',
  'slsa-framework/slsa-github-generator': 'not actively maintained; pipegen uses actions/attest (catalogue §4)',
  'tenable/terrascan': 'archived (catalogue §4)',
  'accurics/terrascan': 'the old name of tenable/terrascan, which is archived (catalogue §4)',
  'tenable/terrascan-action': 'Terrascan is archived (catalogue §4)',
  'accurics/terrascan-action': 'the old name of tenable/terrascan-action; Terrascan is archived (catalogue §4)',
  'aquasecurity/tfsec': 'superseded by Trivy (catalogue §4)',
  'tfsec/tfsec': 'the old name of aquasecurity/tfsec, which Trivy superseded (catalogue §4)',
  'liamg/tfsec': 'the old name of aquasecurity/tfsec, which Trivy superseded (catalogue §4)',
  'aquasecurity/tfsec-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'aquasecurity/tfsec-sarif-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'aquasecurity/tfsec-pr-commenter-action': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec/tfsec-sarif-action': 'the old name of aquasecurity/tfsec-sarif-action; tfsec is superseded by Trivy (catalogue §4)',
  'tfsec/tfsec-pr-commenter-action': 'the old name of aquasecurity/tfsec-pr-commenter-action; tfsec is superseded by Trivy (catalogue §4)',
  'zizmorcore/zizmor-action': 'beta (the no-beta rule, DECISIONS #92); pipegen runs the pinned zizmor binary (catalogue §4)',
  'portswigger/dastardly-github-action': 'Dastardly: unmaintained action with a mutable :latest image (catalogue §4, ruling PS21)',
  'portswigger/dastardly': 'Dastardly: a mutable :latest image from an unmaintained product (catalogue §4, ruling PS21)',
});

/**
 * DECISIONS #122, ruling S6 (J3b): never-listed actions pipegen judges by a commit SHA instead of by name, lowercased
 * `owner/name` → commits checked against upstream. Used ONLY by the coverage mapper (neverListedStep, for a step the repo
 * already has); the reviewed-list loader, discovery and the chooser keep refusing the name at any ref (neverListed).
 * NEVER_REPOS keeps its type. Only aquasecurity/trivy-action is here (owner choice 8: gitleaks-action's reasons don't
 * depend on the pin; setup-trivy had every tag replaced and is never exempt).
 *
 * A trivy-action commit is listed only when, checked on the day, (1) it is on the action's default branch, (2) its
 * action.yaml pins aquasecurity/setup-trivy by a commit SHA that is itself on setup-trivy's default branch and whose
 * action.yaml was read, and (3) that install checks the Trivy binary by checksum. Commits younger than 7 days are not
 * listed (the cooldown pipegen uses for new releases). The upstream state checked on 2026-11-05:
 * - trivy-action commits, master: https://api.github.com/repos/aquasecurity/trivy-action/commits?sha=master and
 *   https://api.github.com/repos/aquasecurity/trivy-action/compare/<sha>...master ("ahead": the commit is on master).
 * - action.yaml at each listed commit: https://raw.githubusercontent.com/aquasecurity/trivy-action/<sha>/action.yaml,
 *   identical at the four commits but for the default `version` (v0.74.0, v0.75.0, v0.76.0, v0.76.1); each pins
 *   `aquasecurity/setup-trivy@81e514348e19b6112ce2a7e3ecbafe19c1e1f567` (v0.3.1) and actions/cache by SHA. entrypoint.sh
 *   (same URL, /entrypoint.sh) is the same file at all four; it downloads nothing (its one network call is the optional
 *   dependency-snapshot upload to GitHub).
 * - setup-trivy 81e514348e19b6112ce2a7e3ecbafe19c1e1f567 is setup-trivy's main
 *   (https://api.github.com/repos/aquasecurity/setup-trivy/compare/81e514348e19b6112ce2a7e3ecbafe19c1e1f567...main:
 *   "identical"); its action.yaml
 *   (https://raw.githubusercontent.com/aquasecurity/setup-trivy/81e514348e19b6112ce2a7e3ecbafe19c1e1f567/action.yaml)
 *   pins actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8 and actions/cache/{restore,save}@9255dc7a253b0ccc959486e2bca901246202afeb
 *   (both on their repos' main) and runs Trivy's install script from aquasecurity/trivy at
 *   75c4dc0f45c5d7ffd05ae26df1e0c666787bdf2a (on trivy's main:
 *   https://api.github.com/repos/aquasecurity/trivy/compare/75c4dc0f45c5d7ffd05ae26df1e0c666787bdf2a...main).
 * - that install script (https://raw.githubusercontent.com/aquasecurity/trivy/75c4dc0f45c5d7ffd05ae26df1e0c666787bdf2a/contrib/install.sh)
 *   downloads the archive and the release's checksums file and refuses an archive whose sha256 differs
 *   (hash_sha256_verify); the four default versions are immutable GitHub releases
 *   (https://api.github.com/repos/aquasecurity/trivy/releases/tags/v0.76.1 and the same for v0.76.0, v0.75.0, v0.74.0:
 *   "immutable": true), so their checksums file can't be changed after publication.
 * Not listed: 38b337fff0a2f984d5be173c99e3f633438167ec (master on 2026-11-05, Trivy v0.76.2 published the same day).
 */
export const NEVER_SAFE_SHAS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'aquasecurity/trivy-action': Object.freeze([
    '8f28faec26515256b6d22074d1d2a8986f4cbd87', // 2026-10-21, Trivy v0.76.1
    '6abccf398f78b4c337599c0656f933d91efb91a0', // 2026-10-14, Trivy v0.76.0
    'c03d123cb480c08c69b054af418ea5e69fe6e57e', // 2026-10-01, Trivy v0.75.0
    'd2a0b60797ff03db6132bd4e2b293f9b37081297', // 2026-08-14, Trivy v0.74.0
  ]),
});

/** Exactly `owner/name@<40 lowercase hex>`: no sub-path, no spaces, no escapes, no other ref form. */
const STEP_AT_SHA = /^([A-Za-z0-9-]{1,39})\/([A-Za-z0-9._-]{1,100})@([0-9a-f]{40})$/;

/**
 * The coverage mapper's never-list check for a step's `uses:` (ruling S6): null when the value is exactly
 * `owner/name@<sha>` for a SHA in NEVER_SAFE_SHAS (owner and name in any letter case, as GitHub reads them); otherwise
 * neverListed's answer, so a tag, a branch, another commit, a sub-path, a fork or a look-alike stays listed. Never use
 * this outside the coverage mapper: the loader, discovery and the chooser refuse the name at any ref.
 */
export function neverListedStep(uses: unknown): NeverHit | null {
  if (typeof uses === 'string') {
    const m = STEP_AT_SHA.exec(uses);
    if (m !== null) {
      const key = `${m[1]}/${m[2]}`.toLowerCase();
      if (Object.hasOwn(NEVER_SAFE_SHAS, key) && (NEVER_SAFE_SHAS[key] as readonly string[]).includes(m[3] as string)) return null;
    }
  }
  return neverListed(uses);
}

/**
 * Repo names refused under ANY owner (fix round 1): a fork or a copy shares the code and often the commit network of
 * the tool it copies. Every non-wildcard NEVER_REPOS name, plus `reviewdog`; a name that starts with one of them and
 * a `-` (`slsa-github-generator-go`, `tfsec-action`) is refused too. NEVER_NAME_ALLOW lists `owner/name` exceptions.
 */
const NEVER_NAMES: ReadonlyMap<string, string> = (() => {
  const m = new Map<string, string>([['reviewdog', 'reviewdog/*']]);
  // the first key with a name (the current repo, listed before its old names) is the one a hit reports
  for (const k of Object.keys(NEVER_REPOS)) if (!k.endsWith('/*') && !m.has(k.slice(k.indexOf('/') + 1))) m.set(k.slice(k.indexOf('/') + 1), k);
  return m;
})();
/** `owner/name` repos allowed although their name is in a never-list family (none needed today). */
export const NEVER_NAME_ALLOW: ReadonlySet<string> = new Set<string>();

/**
 * Images pipegen never runs (P11), by image name (the last part of the path), on any registry and under any
 * namespace: `aquasec/trivy`, `ghcr.io/aquasecurity/trivy` and `public.ecr.aws/aquasecurity/trivy` all end in
 * `trivy`. Kept apart from NEVER_REPOS so the reviewed binary's repo, aquasecurity/trivy, still loads. Docker Hub
 * checked on 2026-10-27: aquasec/trivy, aquasec/tfsec, aquasec/tfsec-ci, aquasec/tfsec-alpine, aquasec/tfsec-scratch,
 * tfsec/tfsec, liamg/tfsec, checkmarx/kics, tenable/terrascan and accurics/terrascan exist.
 */
export const NEVER_IMAGES: Readonly<Record<string, string>> = Object.freeze({
  trivy: 'Trivy runs only as the release binary checked by sha256 and cosign: its Docker Hub images 0.69.5 and 0.69.6 were malicious in March 2026 (catalogue §4, §5)',
  tfsec: 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-ci': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-alpine': 'tfsec is superseded by Trivy (catalogue §4)',
  'tfsec-scratch': 'tfsec is superseded by Trivy (catalogue §4)',
  kics: 'KICS: its Docker Hub tags were overwritten with a data-stealing binary in 2026 (catalogue §4, §5)',
  dastardly: 'Dastardly: a mutable :latest image from an unmaintained product (catalogue §4, ruling PS21)',
  terrascan: 'Terrascan is archived (catalogue §4)',
});

/** A never-list hit: the key it matched, why, and the `owner/name` (or image name) read from the reference. */
export type NeverHit = { key: string; reason: string; ref: string };

/**
 * The never-list check (Plan P Task 5, fix round 1): whether a reference names a NEVER_REPOS repo → the hit; else
 * null. A reference is a repo (`owner/name`), a `uses:` value (any sub-path, `@ref`), an npm `@scope/name`, an image
 * (`[registry/]owner/name[:tag][@digest]`, `docker://…`) or a URL (`https://github.com/owner/name/…`,
 * raw.githubusercontent.com, api.github.com/repos/…). It is read the way the server would: NFKC-folded, lower case,
 * percent-decoded (a broken escape is refused), dot segments resolved. Refused:
 * - a listed `owner/name`, or any repo of a listed `owner/*`;
 * - a never-list name under any owner, or that name followed by `-…` (NEVER_NAMES), unless NEVER_NAME_ALLOW has it;
 * - look-alikes: a full name within Levenshtein distance 2 of a listed one, an owner within 2 of a listed `owner/*`,
 *   or a name of 10 or more characters within 2 of a never-list name;
 * - a repo named by its numeric id (api.github.com/repositories/<id>): pipegen can't tell which repo that is.
 */
export function neverListed(ref: unknown): NeverHit | null {
  const parts = refParts(ref);
  if (parts === null) return null;
  if (parts === 'bad-escape') return { key: '(unreadable)', reason: "it has a broken %-escape, so pipegen can't tell which repo it names", ref: String(ref).slice(0, 100) };
  if (parts === 'repo-id') return { key: '(repo by id)', reason: "it names a GitHub repo by its numeric id, so pipegen can't tell which repo it is", ref: String(ref).slice(0, 100) };
  const [owner, name] = parts;
  const full = name === undefined ? owner : `${owner}/${name}`;
  const found = (key: string) => ({ key, reason: NEVER_REPOS[key] as string, ref: full });
  if (name !== undefined && NEVER_REPOS[full] !== undefined) return found(full);
  if (NEVER_REPOS[`${owner}/*`] !== undefined) return found(`${owner}/*`);
  if (name !== undefined && !NEVER_NAME_ALLOW.has(full)) {
    for (const [family, key] of NEVER_NAMES) if (name === family || name.startsWith(`${family}-`)) return found(key);
  }
  for (const key of Object.keys(NEVER_REPOS)) {
    const [keyOwner, keyName] = key.split('/') as [string, string];
    if (keyName === '*' ? levenshtein(owner, keyOwner) <= 2 : name !== undefined && Math.abs(full.length - key.length) <= 2 && levenshtein(full, key) <= 2) return found(key);
  }
  if (name !== undefined && !NEVER_NAME_ALLOW.has(full)) {
    for (const [family, key] of NEVER_NAMES) if (family.length >= 10 && Math.abs(name.length - family.length) <= 2 && levenshtein(name, family) <= 2) return found(key);
  }
  return null;
}

/**
 * The image check (P11): whether an image reference's name (the last part of its path, any registry, any namespace)
 * is in NEVER_IMAGES → the hit; else null. `aquasec/tfsec-ci:latest`, `ghcr.io/aquasecurity/trivy@sha256:…` and
 * `docker://checkmarx/kics` are all refused.
 */
export function neverImage(ref: unknown): NeverHit | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null;
  const s = decodeRef(ref);
  if (s === null) return { key: '(unreadable)', reason: "it has a broken %-escape, so pipegen can't tell which image it names", ref: ref.slice(0, 100) };
  const path = s.replace(/^docker:\/\//, '').replace(/@sha256:[0-9a-f]*$/, '');
  const last = (path.split('/').pop() ?? '').replace(/[:@].*$/, '');
  const reason = NEVER_IMAGES[last];
  return reason === undefined ? null : { key: last, reason, ref: path.slice(0, 100) };
}

/** NFKC-folded, trimmed, lower case and percent-decoded (until stable); null when an escape is broken. */
function decodeRef(ref: string): string | null {
  let s = lower(ref.normalize('NFKC').trim());
  for (let i = 0; i < 3 && s.includes('%'); i++) {
    try {
      const d = decodeURIComponent(s);
      if (d === s) break;
      s = lower(d.normalize('NFKC'));
    } catch {
      return null;
    }
  }
  return s;
}

/** Path segments with `.` and `..` resolved (a `..` above the start is dropped, as a URL resolver does) and empty ones removed. */
function resolveDots(segs: readonly string[]): string[] {
  const out: string[] = [];
  for (const s of segs) {
    if (s === '' || s === '.') continue;
    if (s === '..') out.pop();
    else out.push(s);
  }
  return out;
}

/** The `owner` and `name` a reference points at (see neverListed), lower case; null when there is no owner. */
function refParts(ref: unknown): [string, string | undefined] | 'bad-escape' | 'repo-id' | null {
  if (typeof ref !== 'string' || ref.length > 2048) return null;
  const decoded = decodeRef(ref);
  if (decoded === null) return 'bad-escape';
  const s = decoded.replace(/^docker:\/\//, '');
  let segs: string[];
  const url = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/]*@)?([^/?#]+)([^?#]*)/.exec(s);
  if (url !== null) {
    const host = (url[1] ?? '').replace(/:\d+$/, '');
    segs = resolveDots((url[2] ?? '').split('/'));
    if (host === 'api.github.com' && segs[0] === 'repositories') return 'repo-id';
    if (host === 'api.github.com' && segs[0] === 'repos') segs.shift();
    if (segs[0] === 'v2') segs.shift(); // a registry API path (ghcr.io/v2/owner/name/…)
  } else {
    segs = resolveDots(s.replace(/^git@[^:/]+:/, '').split('/'));
    // an image's registry host (docker.io, ghcr.io, quay.io, localhost:5000, …) or a URL host without its scheme
    if (segs.length > 2 && /[.:]|^localhost$/.test(segs[0] ?? '')) segs.shift();
    if (segs[0] === 'repos') segs.shift();
    if (segs[0] === 'repositories' && /^\d+$/.test(segs[1] ?? '')) return 'repo-id';
  }
  const owner = segs[0]?.replace(/^@/, '').replace(/[@:#?].*$/, ''); // an npm @scope is its owner
  if (owner === undefined || owner === '') return null;
  const name = segs[1]?.replace(/[@:#?].*$/, '').replace(/\.git$/, '');
  return [owner, name === '' ? undefined : name];
}

/** Levenshtein distance (inputs cut to 300 characters: a GitHub owner/name is at most 140). */
export function levenshtein(x: string, y: string): number {
  const a = x.slice(0, 300);
  const b = y.slice(0, 300);
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min((prev[j - 1] as number) + (a[i - 1] === b[j - 1] ? 0 : 1), (prev[j] as number) + 1, (cur[j - 1] as number) + 1);
    }
    prev = cur;
  }
  return prev[b.length] as number;
}

/**
 * A never-list reason in plain words, for the audit report (ruling P33): the part before any `;`, without the
 * bracketed references to pipegen's own documents (catalogue, DECISIONS, rulings).
 */
export function plainNeverReason(hit: NeverHit): string {
  const first = hit.reason.split(';')[0] ?? hit.reason;
  return first.replace(/\s*\((?:[^()]*?(?:catalogue|DECISIONS|ruling)[^()]*)\)/g, '').trim();
}
