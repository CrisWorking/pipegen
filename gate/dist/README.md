# gate/dist is generated

`index.js` is the pipegen gate action as GitHub runs it (`runs.main` in `../action.yml`). It is built from `../src/index.ts` and
committed because an action is run from its repository, with no build step. `THIRD_PARTY_NOTICES` lists the packages bundled into it.

Do not edit these files. Rebuild them with:

    npm ci
    npm run build:gate

`npm run build:gate` also regenerates `../src/generated/gate-view.ts`, the gate's built-in copy of the reviewed list (no pins in it;
nothing is read from `data/` at run time). CI's `gate-dist` job rebuilds and fails on any difference in `gate/dist` or `gate/src/generated`.

The bundle is ESM and relies on the repository's `"type": "module"`. It imports only `node:` modules and never `child_process`.
