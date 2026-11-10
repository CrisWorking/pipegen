// Plan P PL-B2: a host that deploys a site straight from Git (Cloudflare Pages, Netlify, Vercel) does it outside every
// workflow, so pipegen's checks can't stand before that deploy. The host's config file at the service folder's root says
// so. Each file is read through readTextLimitedWithReason under the repo root: a symbolic link at any level, a binary or
// an over-large file is ignored (the repo is attacker-controlled; an ignored file only means no report line).
import { join } from 'node:path';
import { readTextLimitedWithReason } from './limits.js';
import type { Service } from '../types.js';

export interface HostDeploy { host: string; file: string }

/** Each host config, in the order checked, with the line that marks a Git-integration deploy (null: the file alone does). */
const HOST_CONFIGS: readonly { file: string; host: string; re: RegExp | null }[] = [
  // a wrangler config is a Pages project only with pages_build_output_dir (a Worker config deploys with `wrangler deploy`)
  { file: 'wrangler.toml', host: 'Cloudflare Pages', re: /^\s*pages_build_output_dir\s*=/m },
  { file: 'wrangler.json', host: 'Cloudflare Pages', re: /"pages_build_output_dir"\s*:/ },
  { file: 'wrangler.jsonc', host: 'Cloudflare Pages', re: /"pages_build_output_dir"\s*:/ },
  { file: 'netlify.toml', host: 'Netlify', re: null },
  { file: 'vercel.json', host: 'Vercel', re: null },
];

/** The first host config at the root of `service` (repo-relative `file`), or null. */
export async function hostDeployOf(dir: string, service: Pick<Service, 'path'>): Promise<HostDeploy | null> {
  const folder = service.path === '' || service.path === '.' ? '' : service.path.replace(/\/+$/, '');
  for (const c of HOST_CONFIGS) {
    const rel = folder === '' ? c.file : `${folder}/${c.file}`;
    const read = await readTextLimitedWithReason(join(dir, rel), dir);
    if (!('text' in read)) continue;
    if (c.re !== null && !c.re.test(read.text)) continue;
    return { host: c.host, file: rel };
  }
  return null;
}
