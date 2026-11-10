// PL-F4: published image names can't collide across repositories (ghcr.io/<owner>/<repo>/<service>).
import { describe, expect, it } from 'vitest';
import { publishedImageRepo } from '../src/engine/deploy-steps.js';
import { RenderError } from '../src/engine/render-error.js';

describe('PL-F4 publishedImageRepo', () => {
  it('acme/shop-web + web and acme-shop/web + web → different names', () => {
    expect(publishedImageRepo('acme', 'shop-web', 'web')).not.toBe(publishedImageRepo('acme', 'shop', 'web-web'));
    expect(publishedImageRepo('acme', 'acme-shop', 'web')).not.toBe(publishedImageRepo('acme', 'acme', 'shop-web'));
    expect(publishedImageRepo('acme', 'shop-web', 'web')).toBe('ghcr.io/acme/shop-web/web');
  });
  it('never equals the repository\'s own package ghcr.io/<owner>/<repo>, and is lower case', () => {
    expect(publishedImageRepo('Acme', 'Acme-Shop', 'acme-shop')).toBe('ghcr.io/acme/acme-shop/acme-shop');
    expect(publishedImageRepo('acme', 'acme', 'shop')).not.toBe('ghcr.io/acme/acme-shop');
  });
  it('still refuses a name that is not a plain three-part ghcr.io repository', () => {
    expect(() => publishedImageRepo('acme', 'a/b', 'web')).toThrow(RenderError);
    expect(() => publishedImageRepo('acme', '..', 'web')).toThrow(RenderError);
  });
});
