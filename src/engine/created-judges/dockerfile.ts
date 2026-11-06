// The Dockerfile and .dockerignore judges (v0.2 Plan D, D3; preflight S5 and S6). Both files are new (the guard refuses an edit or an overwrite).
//  - `<service>/Dockerfile` is judged by the SAME rules leaf the creator uses (src/create/dockerfile-rules.ts), with the context taken from the
//    draft: the service found by the file's folder, its reviewed base-image list, `buildsInside` from its scripts, and the port from the service when
//    the reader found one (else the one the file itself exposes, which the leaf then holds to 1..65535 and to a single value).
//    What the creator writes passes; one changed byte or rule gives an issue.
//  - `<service>/.dockerignore` must EQUAL dockerignoreText(service, buildsInside): a fixed text, so no `!` line and no comment can slip in.
// A missing input never reads as "nothing wrong": no service for the folder, two services in it, or an unreadable list all refuse.
// GJ-R1 (Plan J): both are refused for a service the plan builds no image for (noImageServices: a static site, or one that doesn't run).
import { buildsInsideOf, dockerfileProblems, dockerignoreText } from '../../create/dockerfile-rules.js';
import type { CreatedFile, PipelineDraft, Service } from '../../types.js';
import { loadBaseImages } from '../base-images.js';
import { noImageServices } from '../needs.js';
import type { CreatedCtx } from '../created-files.js';

const dirOf = (path: string): string => (path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '');
const rootPrefix = (svcPath: string): string => svcPath.replace(/^(?:\.\/)+/, '').replace(/\/+$/, '').replace(/^\.$/, '');

/** The one service whose folder holds the file, or why there is not exactly one, or why it gets no image (GJ-R1). */
function serviceOf(file: CreatedFile, draft: PipelineDraft): Service | string {
  const owners = draft.profile.services.filter((s) => rootPrefix(s.path) === dirOf(file.path));
  if (owners.length === 0) return 'no service of the repository has this folder';
  if (owners.length > 1) return 'more than one service has this folder, so pipegen can not tell which one the file is for';
  const svc = owners[0] as Service;
  const why = noImageServices(draft.profile, draft.capabilities).get(svc.name);
  if (why !== undefined) return `pipegen builds no image for the service ${JSON.stringify(svc.name.slice(0, 60))} (${why}), so it creates no Dockerfile or .dockerignore for it`;
  return svc;
}

const validPort = (n: unknown): n is number => typeof n === 'number' && Number.isInteger(n) && n >= 1 && n <= 65535;
/** The first port the file exposes (NaN when none, so the leaf refuses the missing or odd EXPOSE). */
function exposedPort(text: string): number {
  const m = /^[ \t]*EXPOSE[ \t]+0*(\d{1,5})(?:\/tcp)?(?:[ \t]|$)/im.exec(text);
  return m === null ? Number.NaN : Number(m[1]);
}

export function dockerfileJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  if (typeof file.content !== 'string') return ['the Dockerfile is not text'];
  const svc = serviceOf(file, ctx.draft);
  if (typeof svc === 'string') return [svc];
  const port = validPort(svc.port) ? svc.port : exposedPort(file.content);
  return dockerfileProblems(file.content, svc, { port, baseImages: loadBaseImages(), buildsInside: buildsInsideOf(svc), scripts: svc.scripts });
}

export function dockerignoreJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  if (typeof file.content !== 'string') return ['the .dockerignore is not text'];
  const svc = serviceOf(file, ctx.draft);
  if (typeof svc === 'string') return [svc];
  return file.content === dockerignoreText(svc, buildsInsideOf(svc)) ? [] : ['the .dockerignore is not the fixed text pipegen writes (it keeps .git, .env files, keys and node_modules out of the image build; nothing may be added, removed or re-included with !)'];
}
