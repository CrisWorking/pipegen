// The compose judge (v0.2 Plan D, D4; preflight S7). `docker-compose.pipegen.yml` is fully computed, so its judge recomputes it from the draft and
// requires byte equality: composeText(draft.profile, the reviewed base-image list, the Dockerfiles the draft creates). Whatever the file holds that
// the computation does not (a key, a mount, a privilege, a changed port, a comment) makes it unequal, so there is no list of forbidden keys to forget.
// The Dockerfiles the draft creates are the app-part files named `<service folder>/Dockerfile`; the creator (createCompose) is given the same list.
import { composeText } from '../../create/compose.js';
import type { CreatedFile, PipelineDraft } from '../../types.js';
import { loadBaseImages } from '../base-images.js';
import type { CreatedCtx } from '../created-files.js';

const createdDockerfiles = (draft: PipelineDraft): string[] =>
  (Array.isArray(draft.created) ? draft.created : []).filter((f) => f !== null && typeof f === 'object' && f.repo === 'app' && f.part === 'docker' && typeof f.path === 'string' && /(?:^|\/)Dockerfile$/.test(f.path)).map((f) => f.path);

export function composeJudge(file: CreatedFile, ctx: CreatedCtx): string[] {
  if (typeof file.content !== 'string') return ['the compose file is not text'];
  const want = composeText(ctx.draft.profile, loadBaseImages(), createdDockerfiles(ctx.draft));
  if (want === null) return ['pipegen would not write a compose file for this repository (no service with a database or broker dependency can run in a container), so it does not write this one'];
  return file.content === want ? [] : ['the compose file is not the file pipegen computes for this repository (it holds only the dependency containers and the services built from their Dockerfiles, each with fixed keys, ports on 127.0.0.1 and ${NAME} references; nothing may be added, removed or changed)'];
}
