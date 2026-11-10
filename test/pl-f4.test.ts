// PL-F4: published image names can't collide across repositories (ghcr.io/<owner>/<repo>/<service>).
import { describe, expect, it } from 'vitest';
import { publishedImageRepo, renderPublishDigestStep } from '../src/engine/deploy-steps.js';
import { RenderError } from '../src/engine/render-error.js';

describe('PL-F4 publishedImageRepo', () => {
  it('acme/shop-web + web and acme/shop + web-web → different names', () => {
    expect(publishedImageRepo('acme', 'shop-web', 'web')).not.toBe(publishedImageRepo('acme', 'shop', 'web-web'));
    expect(publishedImageRepo('acme', 'acme-shop', 'web')).not.toBe(publishedImageRepo('acme', 'acme', 'shop-web'));
    expect(publishedImageRepo('acme', 'shop-web', 'web')).toBe('ghcr.io/acme/shop-web/pipegen-web');
  });
  it('never equals the repository\'s own package ghcr.io/<owner>/<repo>, and is lower case', () => {
    expect(publishedImageRepo('Acme', 'Acme-Shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop/pipegen-acme-shop');
    expect(publishedImageRepo('acme', 'acme', 'shop')).not.toBe('ghcr.io/acme/acme');
  });
  it('never equals the common monorepo name ghcr.io/<owner>/<repo>/<slug> or the old <repo>-<slug> (fold R1 m1)', () => {
    for (const [o, r, svc] of [['acme', 'shop', 'web'], ['Acme', 'Shop', 'Web'], ['o', 'r', 'app'], ['acme', 'shop', 'pipegen-web']]) {
      const lo = (x: string) => x.toLowerCase();
      const got = publishedImageRepo(o, r, svc);
      expect(got).not.toBe(`ghcr.io/${lo(o)}/${lo(r)}/${lo(svc)}`);
      expect(got).not.toBe(`ghcr.io/${lo(o)}/${lo(r)}-${lo(svc)}`);
      expect(got).toBe(`ghcr.io/${lo(o)}/${lo(r)}/pipegen-${lo(svc)}`);
    }
  });
  it('renderPublishDigestStep refuses a name that is not three parts (fold R1 m2)', () => {
    for (const bad of ['ghcr.io/o/r', 'ghcr.io/o/r/app/x', 'ghcr.io//r/app']) expect(() => renderPublishDigestStep('app', bad), bad).toThrow(RenderError);
    expect(() => renderPublishDigestStep('app', 'ghcr.io/o/r/app')).not.toThrow();
  });
  it('still refuses a name that is not a plain three-part ghcr.io repository', () => {
    expect(() => publishedImageRepo('acme', 'a/b', 'web')).toThrow(RenderError);
    expect(() => publishedImageRepo('acme', '..', 'web')).toThrow(RenderError);
  });
});
