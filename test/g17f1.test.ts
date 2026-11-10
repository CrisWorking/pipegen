// G17-F1: the fix round on the G17 final review (L/progress.md "G17-F1"). This file: the secret-name reader over the real assembled files
// (sec I1 = spec-1 M3 = spec-2 I2), the "Verify before deploy" line of a published but unsigned service (sec M2 = spec-1 M5 = spec-2 M3),
// the warn-first sentence (spec-1 M2/M4, spec-2 M2) and the one AI-note filter (sec I2). The --skip deploy case (sec M1) is an e2e case
// (test/cli-run-e2e.test.ts), the sameNames guard a proof case (test/cli-run-proof.test.ts).
import { describe, expect, it } from 'vitest';
import { docFor, isAiNote as runIsAiNote } from '../src/cli/run-parts.js';
import { isAiNote as docsIsAiNote, pipegenDoc } from '../src/deliver/docs.js';
import { workflowSecretNames } from '../src/proof/keys.js';
import { compatCopiesFrom } from '../src/proof/harness.js';
import { escapeLineBreaks } from '../src/engine/yaml-breaks.js';
import { Document, parse, Scalar } from 'yaml';
import { publishedImageRepo } from '../src/engine/deploy-steps.js';
import type { ExistingWorkflow, PipelineDoc } from '../src/types.js';
import { node, planned, profileOf, SEC } from './helpers/assemble.js';
import { REVIEWED } from './helpers/debate-fixtures.js';
import { isWorkflowFile, realAssembled } from './helpers/real-workflows.js';

const read = (content: string): string[] | null => workflowSecretNames([{ content }]);
/** `${{ secrets.NAME }}`, spelled at run time (test/no-secret-literals.test.ts). */
const ref = (name: string): string => `\${{ ${SEC}.${name} }}`;
/** An independent oracle: every `${{ secrets.NAME }}` written in a file's raw text. */
const refsIn = (text: string): string[] => [...text.matchAll(new RegExp(`\\$\\{\\{\\s*${SEC}\\.([A-Za-z_][A-Za-z0-9_]*)\\s*\\}\\}`, 'g'))].map((m) => (m[1] as string).toUpperCase());

describe('G17-F1 sec I1: workflowSecretNames counts `secrets` only as the context of an expression', () => {
  it('keys: workflowSecretNames gives the names (never null) for every real assembled merge, push, nightly and sign workflow, the names each one writes', () => {
    const seen: string[] = [];
    for (const [layout, files] of Object.entries(realAssembled())) {
      const wfs = files.filter(isWorkflowFile);
      expect(wfs.length, layout).toBeGreaterThan(2);
      for (const f of wfs) {
        const names = workflowSecretNames([{ content: f.content }]);
        expect(names, `${layout} ${f.path}`).not.toBeNull();
        expect(names, `${layout} ${f.path}`).toEqual([...new Set(refsIn(f.content))].sort());
        seen.push(f.path);
      }
      // the whole pushed set at once (what run-proof's readBy and sameNames read)
      expect(workflowSecretNames(wfs.map((f) => ({ content: f.content }))), layout).toEqual([...new Set(wfs.flatMap((f) => refsIn(f.content)))].sort());
    }
    // the files the reviewers' probe found null: the central merge and push workflows, the public local merge, push and nightly files
    expect(seen).toEqual(expect.arrayContaining(['.github/workflows/r--merge.yml', '.github/workflows/r--push.yml', '.github/workflows/r--sign.yml', '.github/workflows/pipegen-merge.yml', '.github/workflows/pipegen-nightly.yml']));
    // the secrets job's step name and output names really are in them (else this test would prove nothing)
    const all = Object.values(realAssembled()).flat().map((f) => f.content).join('\n');
    expect(all).toContain(`Stage the files for the ${SEC} scan`);
    expect(all).toContain(`pipegen-out-${SEC}-sha256`);
  });

  it('keys: the word in a name, a step name, an output or job name outside an expression reads no secret; inside one it is the context', () => {
    expect(read(`jobs:\n  ${SEC}:\n    steps:\n      - name: "Stage the files for the ${SEC} scan"\n        run: echo ${ref('A')}\n`)).toEqual(['A']);
    expect(read(`name: check ${SEC}\n`)).toEqual([]);
    expect(read(`needs: [${SEC}]\nenv:\n  K: \${{ needs.${SEC}.outputs.pipegen-out-${SEC}-sha256 }}\n`)).toEqual([]);
    expect(read(`env:\n  K: \${{ steps.x.outputs.pipegen-out-${SEC}-status }}\n`)).toEqual([]);
    // a longer name on one side only (mutants K6, K8: each side is checked on its own)
    expect(read(`env:\n  K: \${{ steps.x.outputs.my-${SEC} }}\n`)).toEqual([]);
    expect(read(`env:\n  K: \${{ ${SEC}-list }}\n`)).toEqual([]);
    // the context, in any letter case and after any operator
    expect(read(`env:\n  K: \${{ !${SEC}.A && (${SEC.toUpperCase()}.B || ${SEC}['c']) }}\n`)).toEqual(['A', 'B', 'C']);
  });

  it('keys: fail closed: a dynamic or whole read inside an expression, a `}}` inside a string, an expression with no end, a bare `if:` expression', () => {
    // the dynamic and whole forms stay null
    expect(read(`run: echo \${{ toJSON(${SEC}) }}\n`)).toBeNull();
    expect(read(`run: echo \${{ ${SEC}[env.N] }}\n`)).toBeNull();
    expect(read(`jobs:\n  a:\n    uses: ./x.yml\n    ${SEC}: inherit\n`)).toBeNull();
    // a `}}` inside a quoted string doesn't end the expression (GitHub's parser reads strings), so what follows is still read
    expect(read(`run: echo \${{ format('}}', ${SEC}.A) }}\n`)).toEqual(['A']);
    expect(read(`run: echo \${{ format('}} ''}}'' ', ${SEC}[env.N]) }}\n`)).toBeNull();
    // an expression with no end: the rest of the text is read as one
    expect(read(`run: echo \${{ ${SEC}.A\n`)).toEqual(['A']);
    expect(read(`run: "echo \${{ x and then the ${SEC} word"\n`)).toBeNull();
    expect(read(`run: "echo \${{ format('}}, ${SEC} ) "\n`)).toBeNull();
    // a key spelled `secrets` in another letter case: never "reads nothing"
    expect(read(`jobs:\n  a:\n    uses: ./x.yml\n    S${SEC.slice(1)}:\n      T: x\n`)).toBeNull();
    expect(read(`jobs:\n  a:\n    uses: ./x.yml\n    \u017f${SEC.slice(1)}: inherit\n`)).toBeNull();
    // `if:` is an expression without `\${{ }}`
    expect(read(`jobs:\n  a:\n    if: ${SEC}.A != ''\n`)).toEqual(['A']);
    expect(read(`jobs:\n  a:\n    steps:\n      - if: toJSON(${SEC}) != ''\n`)).toBeNull();
    expect(read(`jobs:\n  a:\n    "If": ${SEC}.B\n`)).toEqual(['B']);
    // decoded YAML and Unicode case folding still apply inside the expression
    expect(read('env:\n  K: "\\x24{{ \\x73ecrets.ORG_KEY }}"\n')).toEqual(['ORG_KEY']);
    expect(read(`env:\n  K: \${{ \u017f${SEC.slice(1)}.X }}\n`)).toEqual(['X']);
    expect(read(`env:\n  K: \${{ \u017f${SEC.slice(1)} }}\n`)).toBeNull();
  });
});

describe('G17-F1-R2 N1: a YAML 1.1 line break the YAML 1.2 parser reads as content', () => {
  it('keys: workflowSecretNames is null when the raw text holds U+0085, U+2028 or U+2029 (a YAML 1.1 reader ends a comment there)', () => {
    for (const ch of ['\u0085', '\u2028', '\u2029']) {
      // the reviewer's probe P8: in a comment, then a reference a YAML 1.1 reader sees on its own line
      expect(read(`env:\n  A: x # c${ch}  B: ${ref('ORG_H')}\n`), JSON.stringify(ch)).toBeNull();
      // anywhere else in the text too (a quoted value), and as bytes
      expect(read(`env:\n  A: "x${ch}y"\n  B: ${ref('ORG_H')}\n`), JSON.stringify(ch)).toBeNull();
      expect(workflowSecretNames([{ content: Buffer.from(`env:\n  A: x # c${ch}\n`, 'utf8') }]), JSON.stringify(ch)).toBeNull();
    }
    // the control: without them, the names
    expect(read(`env:\n  A: x # c\n  B: ${ref('ORG_H')}\n`)).toEqual(['ORG_H']);
  });
});

describe('G17-F1 round 3 (sec r2 M1): pipegen writes NEL, LS and PS as the YAML escapes \\N, \\L, \\P', () => {
  const RAW = /[\u0085\u2028\u2029]/;
  const CHARS = [['\u0085', '\\N'], ['\u2028', '\\L'], ['\u2029', '\\P']] as const;

  it('compat: a copied job whose step holds U+0085, U+2028 or U+2029 is compared; the copy holds the escape, no raw character, and reads back the same', () => {
    for (const [ch, esc] of CHARS) {
      const r = compatCopiesFrom([{ path: '.github/workflows/ci.yml', content: `on: [pull_request]\njobs:\n  t:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: "a${esc}b"\n        run: "echo a${esc}b"\n` }]);
      expect(r.notCompared, JSON.stringify(ch)).toEqual([]);
      expect(r.files.length).toBe(1);
      const text = (r.files[0] as { content: string }).content;
      expect(RAW.test(text), JSON.stringify(ch)).toBe(false);
      expect(text).toContain(`"echo a${esc}b"`);
      const steps = (parse(text) as { jobs: { t: { steps: { name: string; run: string }[] } } }).jobs.t.steps;
      expect(steps[0]).toEqual({ name: `a${ch}b`, run: `echo a${ch}b` });
      // the N1 check stays quiet on the copy: its names are known
      expect(workflowSecretNames([{ content: text }]), JSON.stringify(ch)).toEqual([]);
    }
  });

  it('escapeLineBreaks: a double-quoted value gets the escape; a character it can not escape (a plain or single-quoted value, a block); a comment gets the escape', () => {
    const doc = (v: string, type: Scalar.Type): string => { const d = new Document({ a: v }); const n = d.get('a', true) as Scalar; n.type = type; return d.toString({ lineWidth: 0 }); };
    for (const [ch, esc] of CHARS) {
      const dq = doc(`x${ch}y`, Scalar.QUOTE_DOUBLE);
      expect(RAW.test(dq), 'the yaml library writes it raw (else this test proves nothing)').toBe(true);
      expect(escapeLineBreaks(dq)).toBe(`a: "x${esc}y"\n`);
      expect(escapeLineBreaks(`a: 'x${ch}y'\n`)).toBeNull();
      expect(escapeLineBreaks(`a: x${ch}y\n`)).toBeNull();
      expect(escapeLineBreaks(`a: |\n  x${ch}y\n`)).toBeNull();
      // in a comment the escape changes nothing a reader reads, and no raw character is left
      expect(escapeLineBreaks(`a: 1 # c${ch}\n`)).toBe(`a: 1 # c${esc}\n`);
      // a backslash right before: the escape still reads back as the character
      expect(parse(escapeLineBreaks(doc(`x\\${ch}`, Scalar.QUOTE_DOUBLE)) as string)).toEqual({ a: `x\\${ch}` });
    }
    expect(escapeLineBreaks('a: "plain"\n')).toBe('a: "plain"\n');
    // a text that doesn't parse is never passed on (mutant E4)
    expect(escapeLineBreaks('a: "x\u2028y"\nb: [\n')).toBeNull();
  });
});

describe('G17-F1 sec M2: "Verify before deploy" of a published but unsigned service', () => {
  const USED = ['sec', 'retsUsed'].join('');
  const deployWf = { path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [USED]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow;
  const DOC: PipelineDoc = { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 120, includedMinutes: 3000 }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] };
  const UNSIGNED_VERIFY = 'Not set up for a signature: pipegen signs nothing in this setup, so there is no signature to check; the verify job still checks that the gate passed and that the head is the one the gate checked (see Signing).';
  const UNSIGNED = 'Not set up: pipegen signs nothing in this setup, so no deploy is checked against a signature (see Signing).';

  it('docs: a private Free repo (mode none) with a published root image: the verify line says the gate pass and the head are still checked', () => {
    const x = planned(profileOf([node({ dockerfile: 'Dockerfile', port: 3000 })], { private: true, plan: 'free', existingWorkflows: [deployWf] }), { over: { centralPin: { repo: 'o/pipelines', sha: 'c'.repeat(40) } } });
    expect(x.draft.signing).toBeUndefined();
    expect(x.draft.capabilities.environments).toBe(false);
    const lines = pipegenDoc({ ...x.draft, doc: DOC }, REVIEWED).content.split('\n');
    const verify = lines.filter((l) => /^- Verify before deploy, service "app"/.test(l));
    expect(verify.length).toBe(1);
    expect(verify[0]?.endsWith(UNSIGNED_VERIFY), verify[0]).toBe(true);
    // a signing line, where the plan lists one, keeps the plain "signs nothing" text
    for (const l of lines.filter((x) => /^- (?:Image signing|Build attestation), service "app"/.test(x))) expect(l.endsWith(UNSIGNED), l).toBe(true);
  });
});

describe('G17-F1 (coordinator): the description before "Verify before deploy" names a signature only when the service is signed', () => {
  const USED = ['sec', 'retsUsed'].join('');
  const deployWf = { path: '.github/workflows/deploy.yml', triggers: ['push'], deploys: true, [USED]: [], jobs: ['deploy'] } as unknown as ExistingWorkflow;
  const DOC: PipelineDoc = { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 120, includedMinutes: 3000 }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] };
  const SIGNED_WHY = 'Checks that the commit being deployed passed the gate and that the image is the signed one.';
  const UNSIGNED_WHY = 'Checks that the commit being deployed passed the gate and that the head is the one the gate checked; pipegen signs nothing in this setup, so no image signature is checked.';
  const UNPUBLISHED_WHY = 'Checks that the commit being deployed passed the gate and that the head is the one the gate checked; pipegen publishes no image of this service, so no image is checked.';
  const verifyLine = (draft: Parameters<typeof pipegenDoc>[0]): string => {
    const lines = pipegenDoc({ ...draft, doc: DOC }, REVIEWED).content.split('\n').filter((l) => /^- Verify before deploy, service "app"/.test(l));
    expect(lines.length).toBe(1);
    return lines[0] as string;
  };
  const web = () => node({ dockerfile: 'Dockerfile', port: 3000 });

  it('docs: a published and signed service: the description says the image is the signed one', () => {
    const x = planned(profileOf([web()], { existingWorkflows: [deployWf] }), { over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: publishedImageRepo('o', 'r', 'app') }] } } });
    const l = verifyLine(x.draft);
    expect(l).toContain(SIGNED_WHY);
    expect(l).not.toContain(UNSIGNED_WHY);
  });

  it('docs: a published but unsigned service: the description names no signature and says the gate pass and the head are checked', () => {
    const x = planned(profileOf([web()], { private: true, plan: 'free', existingWorkflows: [deployWf] }), { over: { centralPin: { repo: 'o/pipelines', sha: 'c'.repeat(40) } } });
    expect(x.draft.signing).toBeUndefined();
    const l = verifyLine(x.draft);
    expect(l).toContain(UNSIGNED_WHY);
    expect(l).not.toContain('the signed one');
  });

  it('docs: an unpublished service (no Dockerfile of its own, or the deploy part skipped): the description names no image', () => {
    const none = planned(profileOf([node({ port: 3000 })], { existingWorkflows: [deployWf] }));
    const signed = planned(profileOf([web()], { existingWorkflows: [deployWf] }), { over: { signing: { mode: 'keyless', images: [{ service: 'app', repo: publishedImageRepo('o', 'r', 'app') }] }, skipped: [{ part: 'deploy', reason: 't' }] } });
    for (const d of [none.draft, signed.draft]) {
      const l = verifyLine(d);
      expect(l).toContain(UNPUBLISHED_WHY);
      expect(l).not.toContain('the signed one');
    }
  });

  it('docs: the glossary says the verify job checks the signed image only where pipegen signs it', () => {
    const doc = pipegenDoc({ ...planned(profileOf()).draft, doc: DOC }, REVIEWED).content;
    expect(doc).toContain('- Verify-first: A job that runs before a deploy and checks the commit passed the gate and, where pipegen signs the image, that the image is the signed one.');
  });
});

describe('G17-F1 spec-1 M2/M4, spec-2 M2: the warn-first switch is made by hand in v0.2', () => {
  it('docs: the Warn mode section says the switch to blocking is by hand and that `npx pipegen update` says how', () => {
    const x = planned(profileOf());
    const doc = pipegenDoc({ ...x.draft, doc: { transcript: [], deployGaps: [], lockNotes: [], estimates: { monthlyMinutes: 1, includedMinutes: 2 }, setupCommand: '', testNotes: [], uncoveredMinimum: [], notes: [] } }, REVIEWED).content;
    expect(doc).toContain('then the nightly run opens an issue to switch it to blocking. In this version that switch is made by hand: `npx pipegen update` names the issue and says how.');
  });
});

describe('G17-F1 sec I2: one AI-note filter', () => {
  it('run-parts: isAiNote is docs.ts\'s (zero-width and other format characters, NFKC and spaces are cleaned first)', () => {
    expect(runIsAiNote).toBe(docsIsAiNote);
    for (const n of ['The AI explained: x', '\u200bThe AI explained: x', ' \ufeffthe\u00a0AI  explained x', '\uff34he AI explained: x']) expect(runIsAiNote(n), JSON.stringify(n)).toBe(true);
    expect(runIsAiNote('The AI explainedness')).toBe(false);
    const doc = docFor({ transcript: [], verify: { gaps: [], notes: ['\u200bThe AI explained: a'], preview: [] }, locks: { notes: [], gateRequired: true }, precommit: { setupCommand: '', notes: [] }, jobs: { notes: [], uncoveredMinimum: [] }, assembledNotes: [], testNotes: ['\u2060The AI explained: b', 'ok'], credits: [], estimates: { monthlyMinutes: 1, includedMinutes: 2 }, prWaitMinutes: 3, strictness: 'standard' });
    expect(JSON.stringify(doc)).not.toMatch(/AI explained/);
    expect(doc.testNotes).toEqual(['ok']);
  });
});
