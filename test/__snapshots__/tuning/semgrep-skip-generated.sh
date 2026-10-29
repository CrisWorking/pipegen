set -euo pipefail
unset CDPATH
pg_fail() { echo "pipegen: $1" >&2; exit 1; }
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
home="$RUNNER_TEMP/pipegen-home/pipegen-out-sast--api"
mkdir -p "$RUNNER_TEMP/pipegen-home" "$home"
sys=(
  /usr/bin/env -i
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "HOME=$home"
)
# tuning: skips the vendored or generated folders services/api/dist, services/api/src/generated for this lint or SAST tool only
rules="$RUNNER_TEMP/pipegen-rules/pipegen-out-sast--api"
for d in services services/api; do
  if [ -L "$d" ] || [ ! -d "$d" ]; then pg_fail "the folder $d is not a real folder inside the repository"; fi
done
cd -- ./services/api
ws="$(cd "$GITHUB_WORKSPACE" && pwd -P)"
case "$(pwd -P)" in "$ws"/*) ;; *) pg_fail "the working folder is outside the repository" ;; esac
if [ -L "$rules"/"$PIPEGEN_ARG_2" ] || [ ! -d "$rules"/"$PIPEGEN_ARG_2" ]; then pg_fail "the rules folder is missing or a link"; fi
# pipegen scope: begin
"${sys[@]}" find . -name .semgrepignore \( -type f -o -type l \) -delete
printf '%s\n' node_modules > .semgrepignore
# pipegen scope: end
out=semgrep.sarif
outdir=.
if [ -e "$out" ] || [ -L "$out" ]; then pg_fail "the result file $out exists before the tool ran, so pipegen will not use it"; fi
[ -d "$outdir" ] && [ ! -L "$outdir" ] || pg_fail "the folder for the result is not a real folder"
pg_env=(
  /usr/bin/env -i
  "HOME=$home"
  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  "RUNNER_TEMP=$RUNNER_TEMP"
  "TMPDIR=$RUNNER_TEMP"
  "PIPEGEN_RULES_URL=$PIPEGEN_RULES_URL"
  "PIPEGEN_RULES_SHA256=$PIPEGEN_RULES_SHA256"
  "PIPEGEN_RULES_TREE=$PIPEGEN_RULES_TREE"
  "PIPEGEN_ARG_0=$PIPEGEN_ARG_0"
  "PIPEGEN_ARG_1=$PIPEGEN_ARG_1"
  "PIPEGEN_ARG_2=$PIPEGEN_ARG_2"
)
rc=0
"${pg_env[@]}" /usr/bin/docker run --rm --pull=never --user "$(id -u):$(id -g)" \
    --security-opt no-new-privileges --cap-drop ALL \
    --network none \
    -v "<cwd>:/src" -w /src \
    -v "$rules/$PIPEGEN_ARG_2:/pipegen-rules:ro" "$PIPEGEN_IMAGE" semgrep scan \
    --exclude "$PIPEGEN_ARG_0" \
    --exclude "$PIPEGEN_ARG_1" \
    --metrics=off --disable-version-check --max-target-bytes=0 \
    --config /pipegen-rules \
    --sarif --output semgrep.sarif || rc=$?
if [ -f "$out" ] && [ ! -L "$out" ]; then
  mkdir -p "$RUNNER_TEMP/pipegen-out"
  mkdir "$RUNNER_TEMP/pipegen-out/pipegen-out-sast--api"
  dest="$RUNNER_TEMP/pipegen-out/pipegen-out-sast--api/semgrep.sarif"
  mv -- "$out" "$dest"
  [ -f "$dest" ] && [ ! -L "$dest" ] || { rm -f -- "$dest"; rc=1; }
  chmod -R a-w "$RUNNER_TEMP/pipegen-out/pipegen-out-sast--api"
else
  echo "pipegen: the tool left no regular result file at $out" >&2
  if [ "$rc" -eq 0 ]; then rc=1; fi
fi
exit "$rc"
# PIPEGEN_ARG values
/dist
/src/generated
javascript
