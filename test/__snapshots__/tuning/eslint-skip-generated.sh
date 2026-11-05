set -euo pipefail
unset CDPATH
pg_fail() { echo "pipegen: $1" >&2; exit 1; }
node="$(command \
    -v node || true)"
[ -n "$node" ] || pg_fail "node was not found; the Node setup step must run first"
nodebin="${node%/*}"
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
home="$RUNNER_TEMP/pipegen-home/pipegen-out-lint--api"
mkdir -p "$RUNNER_TEMP/pipegen-home" "$home"
sys=(
  /usr/bin/env -i
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "HOME=$home"
)
case "$("${sys[@]}" "$node" --version)" in v24.*) ;; *) pg_fail "the node on PATH is not version 24, which the Node setup step installed" ;; esac
# tuning: skips the vendored or generated folders services/api/dist for this lint or SAST tool only
npmdir="$RUNNER_TEMP/pipegen-npm/pipegen-out-lint--api"
mkdir -p "$RUNNER_TEMP/pipegen-npm"
mkdir "$npmdir"
printf '%s' "$PIPEGEN_NPM_LOCK" > "$npmdir/package-lock.json"
printf '%s' "$PIPEGEN_NPM_PACKAGE" > "$npmdir/package.json"
: > "$npmdir/.npmrc"
: > "$npmdir/user.npmrc"
: > "$npmdir/global.npmrc"
pg_env=(
  /usr/bin/env -i
  "HOME=$home"
  "PATH=$nodebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "RUNNER_TEMP=$RUNNER_TEMP"
  "TMPDIR=$RUNNER_TEMP"
)
( cd -- "$npmdir" && "${pg_env[@]}" "$nodebin/npm" ci --ignore-scripts --no-audit --no-fund --userconfig "$npmdir/user.npmrc" --globalconfig "$npmdir/global.npmrc" --workspaces=false --git=/usr/bin/git --registry=https://registry.npmjs.org/ )
for d in services services/api; do
  if [ -L "$d" ] || [ ! -d "$d" ]; then pg_fail "the folder $d is not a real folder inside the repository"; fi
done
cd -- ./services/api
ws="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
case "$(pwd -P)" in "$ws"/*) ;; *) pg_fail "the working folder is outside the repository" ;; esac
printf '%s' "$PIPEGEN_CONFIG" > "$npmdir/eslint.config.mjs"
pg_env=(
  /usr/bin/env -i
  "HOME=$home"
  "PATH=$nodebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "RUNNER_TEMP=$RUNNER_TEMP"
  "TMPDIR=$RUNNER_TEMP"
  "PIPEGEN_ARG_0=$PIPEGEN_ARG_0"
)
js='const fs = require("fs"), path = require("path");
const want = JSON.parse(process.env.PIPEGEN_NPM_EXPECT);
let bad = 0;
const fail = (m) => { console.error("pipegen: " + m); bad = 1; };
let top = null;
try { top = fs.lstatSync("node_modules"); } catch (e) { top = null; }
if (!top || !top.isDirectory() || top.isSymbolicLink()) { fail("node_modules is not a real folder"); process.exit(1); }
const root = fs.realpathSync("node_modules");
let hidden = {};
try { hidden = JSON.parse(fs.readFileSync("node_modules/.package-lock.json", "utf8")).packages || {}; } catch (e) { hidden = {}; }
for (const w of want) {
  const dir = path.join("node_modules", w.name);
  let st = null;
  try { st = fs.lstatSync(dir); } catch (e) { st = null; }
  if (!st || !st.isDirectory() || st.isSymbolicLink()) { fail(w.name + " is not a real folder in node_modules"); continue; }
  if (!fs.realpathSync(dir).startsWith(root + path.sep)) { fail(w.name + " is outside node_modules"); continue; }
  let version = null;
  try { version = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")).version; } catch (e) { version = null; }
  if (version !== w.version) fail(w.name + " is " + version + ", not the reviewed " + w.version);
  const h = hidden["node_modules/" + w.name];
  if (!h || h.integrity !== w.integrity || h.resolved !== w.resolved) fail(w.name + " was not installed from the reviewed registry tarball");
}
process.exit(bad);'
( cd -- "$npmdir" && "${pg_env[@]}" "PIPEGEN_NPM_EXPECT=$PIPEGEN_NPM_EXPECT" "$nodebin/node" -e "$js" )
chmod -R a-w "$npmdir"
rc=0
"${pg_env[@]}" "$nodebin/node" "$npmdir/node_modules/eslint/bin/eslint.js" \
    --ignore-pattern "$PIPEGEN_ARG_0" \
    --config "$npmdir/eslint.config.mjs" --max-warnings 0 . || rc=$?
exit "$rc"
# PIPEGEN_ARG values
dist/**
