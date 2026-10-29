import { describe, expect, it } from 'vitest';
import { ArtifactNameError, resultArtifactName, resultArtifactNames, slug } from '../src/engine/artifact-names.js';
import { RESULT_ARTIFACT_PREFIX } from '../src/types.js';

describe('slug', () => {
  it('slug: lower case [a-z0-9-] only, at most 40 characters, no edge or doubled dashes', () => {
    expect(slug('My App')).toBe('my-app');
    expect(slug('@scope/pkg.name')).toBe('scope-pkg-name');
    expect(slug('a---b')).toBe('a-b');
    expect(slug('--x--')).toBe('x');
    expect(slug('x'.repeat(100))).toHaveLength(40);
    expect(slug(`${'a'.repeat(39)}-b`)).toBe('a'.repeat(39)); // cut at 40 leaves no trailing dash
    expect(slug('Ünïcode\u202e\n${{ x }}')).toMatch(/^[a-z0-9-]*$/);
  });

  it('slug: nothing left after cleaning → throws', () => {
    expect(() => slug('///')).toThrow(ArtifactNameError);
    expect(() => slug('')).toThrow(ArtifactNameError);
  });
});

describe('resultArtifactName', () => {
  it('resultArtifactName: RESULT_ARTIFACT_PREFIX + needId; a service adds -- and its slug; base adds base-', () => {
    expect(resultArtifactName('sast')).toBe(`${RESULT_ARTIFACT_PREFIX}sast`);
    expect(resultArtifactName('sast', 'API Server')).toBe(`${RESULT_ARTIFACT_PREFIX}sast--api-server`);
    expect(resultArtifactName('sast', undefined, { base: true })).toBe(`${RESULT_ARTIFACT_PREFIX}base-sast`);
    expect(resultArtifactName('sast', 'web', { base: true })).toBe(`${RESULT_ARTIFACT_PREFIX}base-sast--web`);
  });

  it('resultArtifactName: two services with the same need get different names', () => {
    expect(resultArtifactName('sast', 'api')).not.toBe(resultArtifactName('sast', 'web'));
  });

  it('resultArtifactName: a need id that is not a plain id is refused', () => {
    for (const bad of ['', 'Sast', 'sast/../x', 'a b', '${{ x }}', '-x', 'x\n', 'sast--api', 'base-sast']) expect(() => resultArtifactName(bad), bad).toThrow(ArtifactNameError);
  });

  it('resultArtifactName: a single call can not collide with another: no `--` or leading base- in a need id', () => {
    expect(() => resultArtifactName('sast--api')).toThrow(ArtifactNameError);
    expect(() => resultArtifactName('base-sast')).toThrow(ArtifactNameError);
    expect(resultArtifactName('dependency-review')).toBe(`${RESULT_ARTIFACT_PREFIX}dependency-review`);
  });

  it('resultArtifactNames: a collision after slugging throws; distinct names pass', () => {
    const ok = resultArtifactNames([{ needId: 'sast', service: 'api' }, { needId: 'sast', service: 'web' }, { needId: 'secrets' }]);
    expect(ok).toEqual([`${RESULT_ARTIFACT_PREFIX}sast--api`, `${RESULT_ARTIFACT_PREFIX}sast--web`, `${RESULT_ARTIFACT_PREFIX}secrets`]);
    expect(() => resultArtifactNames([{ needId: 'sast', service: 'My App' }, { needId: 'sast', service: 'my-app' }])).toThrow(/collide/);
    // a long name cut at 40 characters can collide with another
    const long = 'x'.repeat(45);
    expect(() => resultArtifactNames([{ needId: 'sast', service: `${long}1` }, { needId: 'sast', service: `${long}2` }])).toThrow(ArtifactNameError);
  });
});
