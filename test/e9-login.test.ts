// E9 (gate-v0.2.2 batch, preflight §5 "EMU logins"; carry E0c): Enterprise Managed Users have logins of the form
// `<normalized name>_<shortcode>` (one underscore, never first or last; GitHub's limit of 39 characters holds for them too). Before E9
// every login pattern refused them: the gate skipped a CODEOWNERS line naming one (so the file fell to an earlier rule), the gate
// adapter refused to ask an EMU reviewer's permission (the gate failed, closed), the judge refused pipegen's own CODEOWNERS block, and
// the proof refused to push to an EMU user's scratch repo. One leaf (gate/src/login.ts) now holds both shapes. Written first.
import { describe, expect, it } from 'vitest';
import { API_ROOT, githubAdapter, type AdapterOptions } from '../gate/src/github-adapter.js';
import { codeOwners, LOGIN_RE, ownersOf } from '../gate/src/integrity.js';
import { API_LOGIN_RE, STRICT_LOGIN_RE } from '../gate/src/login.js';
import { codeownersOwnerProblem } from '../src/engine/created-builders.js';
import { checkPushUrl } from '../src/proof/git.js';

const TK = ['to', 'ken'].join('');
const CRED = ['gh', 's_', 'Qw8'.repeat(12)].join('');

const BAD = ['_alice', 'alice_', '_', 'alice__acme', 'a_b_c', 'alice_acme_x', `${'a'.repeat(35)}_acme`, `${'a'.repeat(40)}`, 'alice_ac-me', '-alice', 'alice acme', 'alice_ac.me', ''];
const GOOD = ['alice_acme', 'a_b', 'Alice-Smith_ACME1', 'alice', 'Alice-1', `${'a'.repeat(34)}_acme`, 'a'.repeat(39)];

describe('E9: EMU logins', () => {
  it('codeowners: EMU login @alice_acme accepted in the gate and in the judge', () => {
    // the gate: the line is read (not skipped as invalid) and @alice_acme owns the file, lower-cased like any login
    const rules = codeOwners('* @root\nsrc/** @alice_acme @Bob_Corp\n');
    expect(ownersOf(rules, 'src/a.js')).toEqual(['alice_acme', 'bob_corp']);
    expect(LOGIN_RE.exec('@alice_acme')?.[1]).toBe('alice_acme');
    // the judge of pipegen's own CODEOWNERS block
    expect(codeownersOwnerProblem(['@alice_acme', '@bob'])).toBeNull();
    expect(codeownersOwnerProblem(['@alice_acme', '@ALICE_ACME'])).toMatch(/twice/);
  });

  it('gate adapter: EMU reviewer login accepted', async () => {
    const seen: string[] = [];
    const fetch = (async (input: string | URL | Request) => {
      seen.push(String(input));
      return new Response(JSON.stringify({ permission: 'write' }), { status: 200, headers: { 'content-type': 'application/json' } });
    }) as typeof globalThis.fetch;
    const gh = githubAdapter({ [TK]: CRED, fetch } as unknown as AdapterOptions);
    await gh.collaboratorPermission('acme', 'app', 'alice_acme');
    expect(seen).toEqual([`${API_ROOT}/repos/acme/app/collaborators/alice_acme/permission`]);
    for (const bad of ['_alice', 'alice_', 'a_b_c', 'alice__acme', `${'a'.repeat(35)}_acme`]) {
      await expect(gh.collaboratorPermission('acme', 'app', bad), bad).rejects.toThrow(/not a GitHub login/);
    }
    expect(seen).toHaveLength(1);
  });

  it("login: _ at the start or end, two _ or longer than GitHub's limit → refused", () => {
    for (const b of BAD) {
      expect(STRICT_LOGIN_RE.test(b), `strict ${b}`).toBe(false);
      expect(LOGIN_RE.test(`@${b}`), `gate @${b}`).toBe(false);
      expect(codeownersOwnerProblem([`@${b}`]), `judge @${b}`).not.toBeNull();
      if (b !== 'alice_ac-me') expect(API_LOGIN_RE.test(b), `api ${b}`).toBe(false);   // the API shape keeps older accounts' inner/trailing hyphens before the suffix
    }
    // a CODEOWNERS line with such an owner is invalid and skipped whole, as GitHub does
    expect(ownersOf(codeOwners('* @root\nsrc/** @alice_\n'), 'src/a.js')).toEqual(['root']);
    for (const g of GOOD) {
      expect(STRICT_LOGIN_RE.test(g), `strict ${g}`).toBe(true);
      expect(API_LOGIN_RE.test(g), `api ${g}`).toBe(true);
    }
    // the API shape is unchanged for plain logins (a trailing hyphen of an older account still reads); only the EMU suffix is new
    expect(API_LOGIN_RE.test('old-')).toBe(true);
    expect(STRICT_LOGIN_RE.test('old-')).toBe(false);
  });

  it('E0c: the proof pushes to an EMU user\'s scratch repo, and only with the same login rule', () => {
    expect(checkPushUrl('https://github.com/alice_acme/pipegen-proof-shop.git', 'alice_acme', 'shop')).toBe('scratch');
    expect(checkPushUrl('https://github.com/alice_acme/pipelines.git', 'alice_acme', 'shop')).toBe('central');
    for (const owner of ['_alice', 'alice_', 'a_b_c', `${'a'.repeat(35)}_acme`]) {
      expect(() => checkPushUrl(`https://github.com/${owner}/pipelines.git`, owner, 'shop'), owner).toThrow(/plain GitHub name/);
    }
  });
});
