// Command-line grammars of the tools whose argv the reviewed-list loader checks (Plan P Task 5, fix round 1). Generated
// once from each tool's own source at the pinned version, read with read-only `gh api` on 2026-10-27; re-generate when a
// pin moves. Each grammar lists every flag the tool accepts and whether it takes a value, so the loader can read argv
// the way the tool does (a value-taking flag swallows the next word, `--` ends the flags) and refuse any flag it
// doesn't know. Leaf module: no imports.

/**
 * A tool's flags: `value` flags take a value (the next word, or `=v`); `bool` flags take none (`=v` sets a bool);
 * `optional` flags take a value only as `--flag=v` (pflag NoOptDefVal: alone they use their default, and never
 * swallow the next word); `shorts` maps a short name to its long name.
 */
export interface FlagGrammar {
  readonly value: ReadonlySet<string>; readonly bool: ReadonlySet<string>; readonly optional: ReadonlySet<string>; readonly shorts: Readonly<Record<string, string>>;
}
const grammar = (value: readonly string[], bool: readonly string[], shorts: Record<string, string>, optional: readonly string[] = []): FlagGrammar => ({
  value: new Set(value.filter((v) => !optional.includes(v))), bool: new Set(bool), optional: new Set(optional), shorts: Object.freeze(shorts),
});

/**
 * Trivy v0.76.0, by subcommand (pflag: `--long`, `-s`, glued `-svalue`, combined bool shorthands). Source: the
 * "Options" and "Options inherited from parent commands" of docs/guide/references/configuration/cli/trivy_config.md,
 * trivy_image.md and trivy_filesystem.md at tag v0.76.0 (a flag with a type word takes a value).
 */
export const TRIVY_GRAMMAR: Readonly<Record<'config' | 'image' | 'fs', FlagGrammar>> = {
  config: grammar([
    'ansible-extra-vars', 'ansible-inventory', 'ansible-playbook', 'cacert', 'cache-backend', 'cache-dir',
    'cache-ttl', 'cf-params', 'check-namespaces', 'checks-bundle-repository', 'compliance', 'config', 'config-check',
    'config-data', 'config-file-schemas', 'enable-modules', 'exit-code', 'file-patterns', 'format',
    'helm-api-versions', 'helm-kube-version', 'helm-set', 'helm-set-file', 'helm-set-string', 'helm-values',
    'ignore-policy', 'ignorefile', 'k8s-version', 'misconfig-scanners', 'module-dir', 'output', 'output-plugin-arg',
    'password', 'raw-config-scanners', 'redis-ca', 'redis-cert', 'redis-key', 'registry-token', 'rego-error-limit',
    'render-cause', 'report', 'severity', 'skip-dirs', 'skip-files', 'table-mode', 'template', 'tf-vars', 'timeout',
    'username',
  ], [
    'debug', 'disable-telemetry', 'generate-default-config', 'help', 'include-deprecated-checks',
    'include-non-failures', 'insecure', 'password-stdin', 'quiet', 'redis-tls', 'skip-check-update',
    'skip-version-check', 'tf-exclude-downloaded-modules', 'trace-rego', 'version',
  ], {'f': 'format', 'h': 'help', 'o': 'output', 's': 'severity', 't': 'template', 'c': 'config', 'd': 'debug', 'q': 'quiet', 'v': 'version'}),
  image: grammar([
    'ansible-extra-vars', 'ansible-inventory', 'ansible-playbook', 'cacert', 'cache-backend', 'cache-dir',
    'cache-ttl', 'check-namespaces', 'checks-bundle-repository', 'compliance', 'config', 'config-check',
    'config-data', 'config-file-schemas', 'custom-headers', 'db-repository', 'detection-priority', 'distro',
    'docker-host', 'enable-modules', 'exit-code', 'exit-on-eol', 'file-patterns', 'format', 'helm-api-versions',
    'helm-kube-version', 'helm-set', 'helm-set-file', 'helm-set-string', 'helm-values', 'ignore-policy',
    'ignore-status', 'ignored-licenses', 'ignorefile', 'image-config-scanners', 'image-src', 'input',
    'java-db-repository', 'license-confidence-level', 'max-image-size', 'misconfig-scanners', 'module-dir', 'output',
    'output-plugin-arg', 'parallel', 'password', 'pkg-relationships', 'pkg-types', 'platform', 'podman-host',
    'raw-config-scanners', 'redis-ca', 'redis-cert', 'redis-key', 'registry-token', 'rego-error-limit', 'rekor-url',
    'render-cause', 'report', 'sbom-sources', 'scanners', 'secret-config', 'server', 'severity', 'skip-dirs',
    'skip-files', 'table-mode', 'template', 'timeout', 'token', 'token-header', 'username', 'vex',
    'vuln-severity-source',
  ], [
    'debug', 'dependency-tree', 'disable-telemetry', 'download-db-only', 'download-java-db-only',
    'generate-default-config', 'help', 'ignore-unfixed', 'include-deprecated-checks', 'include-non-failures',
    'insecure', 'license-full', 'list-all-pkgs', 'no-progress', 'offline-scan', 'password-stdin', 'quiet',
    'redis-tls', 'removed-pkgs', 'show-suppressed', 'skip-check-update', 'skip-db-update', 'skip-java-db-update',
    'skip-version-check', 'skip-vex-repo-update', 'tf-exclude-downloaded-modules', 'trace-rego', 'version',
  ], {'f': 'format', 'h': 'help', 'o': 'output', 's': 'severity', 't': 'template', 'c': 'config', 'd': 'debug', 'q': 'quiet', 'v': 'version'}),
  fs: grammar([
    'ansible-extra-vars', 'ansible-inventory', 'ansible-playbook', 'cacert', 'cache-backend', 'cache-dir',
    'cache-ttl', 'cf-params', 'check-namespaces', 'checks-bundle-repository', 'compliance', 'config', 'config-check',
    'config-data', 'config-file-schemas', 'custom-headers', 'db-repository', 'detection-priority', 'distro',
    'enable-modules', 'exit-code', 'file-patterns', 'format', 'helm-api-versions', 'helm-kube-version', 'helm-set',
    'helm-set-file', 'helm-set-string', 'helm-values', 'ignore-policy', 'ignore-status', 'ignored-licenses',
    'ignorefile', 'java-db-repository', 'license-confidence-level', 'misconfig-scanners', 'module-dir', 'output',
    'output-plugin-arg', 'parallel', 'password', 'pkg-relationships', 'pkg-types', 'raw-config-scanners', 'redis-ca',
    'redis-cert', 'redis-key', 'registry-token', 'rego-error-limit', 'rekor-url', 'render-cause', 'report',
    'sbom-sources', 'scanners', 'secret-config', 'server', 'severity', 'skip-dirs', 'skip-files', 'table-mode',
    'template', 'tf-vars', 'timeout', 'token', 'token-header', 'username', 'vex', 'vuln-severity-source',
  ], [
    'debug', 'dependency-tree', 'disable-telemetry', 'download-db-only', 'download-java-db-only',
    'generate-default-config', 'help', 'ignore-unfixed', 'include-deprecated-checks', 'include-dev-deps',
    'include-non-failures', 'insecure', 'license-full', 'list-all-pkgs', 'no-progress', 'offline-scan',
    'password-stdin', 'quiet', 'redis-tls', 'show-suppressed', 'skip-check-update', 'skip-db-update',
    'skip-java-db-update', 'skip-version-check', 'skip-vex-repo-update', 'tf-exclude-downloaded-modules',
    'trace-rego', 'version',
  ], {'f': 'format', 'h': 'help', 'o': 'output', 's': 'severity', 't': 'template', 'c': 'config', 'd': 'debug', 'q': 'quiet', 'v': 'version'}),
};

/**
 * Nuclei v3.11.1 (projectdiscovery/goflags v0.1.75: `-name` or `--name`, `-name=value`, short names are other names,
 * no combined shorthands). Source: every flagSet.*Var(P) call in cmd/nuclei/main.go at tag v3.11.1, plus `max-time`
 * (`mt`) from goflags v0.1.75 AddCommonFlags (common_flags.go). Bool, callback and dynamic flags take no separate value.
 */
export const NUCLEI_GRAMMAR: FlagGrammar = grammar([
  'attack-type', 'author', 'bulk-size', 'cdp-endpoint', 'client-ca', 'client-cert', 'client-key', 'concurrency',
  'config', 'dashboard-upload', 'dast-server-address', 'dast-server-token', 'dialer-keep-alive', 'error-log',
  'exclude-hosts', 'exclude-id', 'exclude-matchers', 'exclude-severity', 'exclude-tags', 'exclude-templates',
  'exclude-type', 'fuzz-aggression', 'fuzz-out-scope', 'fuzz-param-frequency', 'fuzz-scope', 'fuzzing-mode',
  'fuzzing-type', 'header', 'headless-bulk-size', 'headless-concurrency', 'headless-options', 'honeypot-threshold',
  'http-api-endpoint', 'include-tags', 'include-templates', 'input-mode', 'input-read-timeout',
  'interactions-cache-size', 'interactions-cooldown-period', 'interactions-eviction', 'interactions-poll-duration',
  'interactsh-server', 'interactsh-token', 'interface', 'ip-version', 'js-concurrency', 'json-export',
  'jsonl-export', 'list', 'markdown-export', 'max-host-error', 'max-redirects', 'max-time', 'metrics-port',
  'new-templates-version', 'output', 'page-timeout', 'payload-concurrency', 'pdf-export', 'probe-concurrency',
  'profile', 'profile-mem', 'project-path', 'prompt', 'proxy', 'rate-limit', 'rate-limit-duration',
  'rate-limit-minute', 'redact', 'report-config', 'report-db', 'resolvers', 'response-size-read',
  'response-size-save', 'resume', 'retries', 'sarif-export', 'scan-id', 'scan-name', 'scan-strategy', 'secret-file',
  'severity', 'sni', 'source-ip', 'stats-interval', 'store-resp-dir', 'tags', 'target', 'targets-inline', 'team-id',
  'template-condition', 'template-id', 'template-loading-concurrency', 'template-url', 'templates', 'timeout',
  'trace-log', 'track-error', 'type', 'uncover-engine', 'uncover-field', 'uncover-limit', 'uncover-query',
  'uncover-ratelimit', 'update-template-dir', 'var', 'var-dump-limit', 'var-file-paths', 'workflow-url', 'workflows',
], [
  'allow-local-file-access', 'auth', 'automatic-scan', 'cloud-upload', 'code', 'dashboard', 'dast', 'dast-report',
  'dast-server', 'debug', 'debug-req', 'debug-resp', 'disable-clustering', 'disable-redirects',
  'disable-unsigned-templates', 'disable-update-check', 'display-fuzz-points', 'enable-global-matchers',
  'enable-pprof', 'enable-self-contained', 'env-vars', 'file', 'follow-host-redirects', 'follow-redirects',
  'force-http2', 'fuzz', 'hang-monitor', 'headless', 'health-check', 'honeypot-detect', 'http-stats', 'include-rr',
  'jsonl', 'leave-default-ports', 'list-dsl-function', 'list-headless-action', 'matcher-status', 'new-templates',
  'no-color', 'no-httpx', 'no-interactsh', 'no-meta', 'no-mhe', 'no-stdin', 'no-strict-syntax', 'omit-raw',
  'omit-template', 'passive', 'per-host-rate-limit', 'prefetch-secrets', 'preflight-portscan', 'profile-list',
  'project', 'proxy-internal', 'required-only', 'reset', 'restrict-local-network-access', 'scan-all-ips',
  'show-browser', 'show-match-line', 'show-var-dump', 'sign', 'silent', 'skip-format-validation', 'stats',
  'stats-json', 'stop-at-first-match', 'store-resp', 'stream', 'suppress-honeypot', 'system-chrome',
  'system-resolvers', 'template-display', 'templates-version', 'tgl', 'timestamp', 'tl', 'tls-impersonate',
  'uncover', 'update', 'update-templates', 'validate', 'vars-text-templating', 'verbose', 'version', 'vv', 'ztls',
], {'u': 'target', 'l': 'list', 'eh': 'exclude-hosts', 'sa': 'scan-all-ips', 'iv': 'ip-version', 'im': 'input-mode', 'ro': 'required-only', 'sfv': 'skip-format-validation', 'vtt': 'vars-text-templating', 'vfp': 'var-file-paths', 'nt': 'new-templates', 'ntv': 'new-templates-version', 'as': 'automatic-scan', 't': 'templates', 'turl': 'template-url', 'ai': 'prompt', 'w': 'workflows', 'wurl': 'workflow-url', 'nss': 'no-strict-syntax', 'td': 'template-display', 'dut': 'disable-unsigned-templates', 'esc': 'enable-self-contained', 'egm': 'enable-global-matchers', 'a': 'author', 'etags': 'exclude-tags', 'itags': 'include-tags', 'id': 'template-id', 'eid': 'exclude-id', 'it': 'include-templates', 'et': 'exclude-templates', 'em': 'exclude-matchers', 's': 'severity', 'es': 'exclude-severity', 'pt': 'type', 'ept': 'exclude-type', 'tc': 'template-condition', 'o': 'output', 'sresp': 'store-resp', 'srd': 'store-resp-dir', 'nc': 'no-color', 'j': 'jsonl', 'irr': 'include-rr', 'or': 'omit-raw', 'ot': 'omit-template', 'nm': 'no-meta', 'ts': 'timestamp', 'rdb': 'report-db', 'ms': 'matcher-status', 'me': 'markdown-export', 'se': 'sarif-export', 'je': 'json-export', 'jle': 'jsonl-export', 'pe': 'pdf-export', 'rd': 'redact', 'tp': 'profile', 'tpl': 'profile-list', 'fr': 'follow-redirects', 'fhr': 'follow-host-redirects', 'mr': 'max-redirects', 'dr': 'disable-redirects', 'rc': 'report-config', 'H': 'header', 'V': 'var', 'r': 'resolvers', 'sr': 'system-resolvers', 'dc': 'disable-clustering', 'fh2': 'force-http2', 'ev': 'env-vars', 'cc': 'client-cert', 'ck': 'client-key', 'ca': 'client-ca', 'sml': 'show-match-line', 'dka': 'dialer-keep-alive', 'lfa': 'allow-local-file-access', 'lna': 'restrict-local-network-access', 'i': 'interface', 'at': 'attack-type', 'sip': 'source-ip', 'rsr': 'response-size-read', 'rss': 'response-size-save', 'tlsi': 'tls-impersonate', 'hae': 'http-api-endpoint', 'iserver': 'interactsh-server', 'itoken': 'interactsh-token', 'ni': 'no-interactsh', 'ft': 'fuzzing-type', 'fm': 'fuzzing-mode', 'dts': 'dast-server', 'dtr': 'dast-report', 'dtst': 'dast-server-token', 'dtsa': 'dast-server-address', 'dfp': 'display-fuzz-points', 'fa': 'fuzz-aggression', 'cs': 'fuzz-scope', 'cos': 'fuzz-out-scope', 'uc': 'uncover', 'uq': 'uncover-query', 'ue': 'uncover-engine', 'uf': 'uncover-field', 'ul': 'uncover-limit', 'ur': 'uncover-ratelimit', 'rl': 'rate-limit', 'rld': 'rate-limit-duration', 'rlm': 'rate-limit-minute', 'bs': 'bulk-size', 'c': 'concurrency', 'hbs': 'headless-bulk-size', 'headc': 'headless-concurrency', 'jsc': 'js-concurrency', 'pc': 'payload-concurrency', 'prc': 'probe-concurrency', 'tlc': 'template-loading-concurrency', 'ldp': 'leave-default-ports', 'mhe': 'max-host-error', 'te': 'track-error', 'nmhe': 'no-mhe', 'spm': 'stop-at-first-match', 'ss': 'scan-strategy', 'irt': 'input-read-timeout', 'nh': 'no-httpx', 'sb': 'show-browser', 'ho': 'headless-options', 'sc': 'system-chrome', 'cdpe': 'cdp-endpoint', 'lha': 'list-headless-action', 'dreq': 'debug-req', 'dresp': 'debug-resp', 'p': 'proxy', 'pi': 'proxy-internal', 'ldf': 'list-dsl-function', 'tlog': 'trace-log', 'elog': 'error-log', 'hm': 'hang-monitor', 'v': 'verbose', 'svd': 'show-var-dump', 'vdl': 'var-dump-limit', 'ep': 'enable-pprof', 'tv': 'templates-version', 'hc': 'health-check', 'up': 'update', 'ut': 'update-templates', 'ud': 'update-template-dir', 'duc': 'disable-update-check', 'hpd': 'honeypot-detect', 'hpt': 'honeypot-threshold', 'shp': 'suppress-honeypot', 'sj': 'stats-json', 'si': 'stats-interval', 'mp': 'metrics-port', 'hps': 'http-stats', 'tid': 'team-id', 'cup': 'cloud-upload', 'sid': 'scan-id', 'sname': 'scan-name', 'pd': 'dashboard', 'pdu': 'dashboard-upload', 'sf': 'secret-file', 'ps': 'prefetch-secrets', 'mt': 'max-time'});

/**
 * betterleaks v1.9.0 (cobra/pflag). Source at tag v1.9.0: the root's persistent flags in cmd/root.go (lines 81-127),
 * and the scan subcommands pipegen may run: `git` (cmd/git.go), `dir` (cmd/directory.go), `stdin` (cmd/stdin.go).
 * cmd/rule_flags.go expands `-dr` and `-ir` to --disable-rule and --isolate-rule before parsing. `--redact` takes an
 * optional value: cmd/root.go:95 sets its NoOptDefVal to "100", so `--redact` alone never swallows the next word.
 */
export const BETTERLEAKS_GRAMMAR: Readonly<Record<'git' | 'dir' | 'stdin', FlagGrammar>> = {
  git: grammar([
    'baseline-path', 'confidence', 'config', 'diagnostics', 'diagnostics-dir', 'disable-rule', 'enable-rule',
    'exit-code', 'experiments', 'git-workers', 'gitleaks-ignore-path', 'isolate-rule', 'log-level', 'log-opts',
    'match-context', 'max-archive-depth', 'max-decode-depth', 'max-target-megabytes', 'platform', 'redact',
    'regex-engine', 'regexp-engine', 'report-format', 'report-path', 'report-template', 'timeout',
    'validation-env-vars', 'validation-max-request', 'validation-max-requests', 'validation-rps',
    'validation-rps-rule', 'validation-status', 'validation-timeout', 'validation-workers',
  ], [
    'help', 'ignore-gitleaks-allow', 'legacy-print', 'no-banner', 'no-color', 'pre-commit', 'staged', 'validation',
    'validation-debug', 'validation-extract-empty', 'verbose',
  ], {'c': 'config', 'r': 'report-path', 'f': 'report-format', 'b': 'baseline-path', 'l': 'log-level', 'v': 'verbose', 'i': 'gitleaks-ignore-path', 'h': 'help'}, ['redact']),
  dir: grammar([
    'baseline-path', 'confidence', 'config', 'diagnostics', 'diagnostics-dir', 'disable-rule', 'enable-rule',
    'exit-code', 'experiments', 'gitleaks-ignore-path', 'isolate-rule', 'log-level', 'match-context',
    'max-archive-depth', 'max-decode-depth', 'max-target-megabytes', 'redact', 'regex-engine', 'regexp-engine',
    'report-format', 'report-path', 'report-template', 'timeout', 'validation-env-vars', 'validation-max-request',
    'validation-max-requests', 'validation-rps', 'validation-rps-rule', 'validation-status', 'validation-timeout',
    'validation-workers',
  ], [
    'follow-symlinks', 'help', 'ignore-gitleaks-allow', 'legacy-print', 'no-banner', 'no-color', 'validation',
    'validation-debug', 'validation-extract-empty', 'verbose',
  ], {'c': 'config', 'r': 'report-path', 'f': 'report-format', 'b': 'baseline-path', 'l': 'log-level', 'v': 'verbose', 'i': 'gitleaks-ignore-path', 'h': 'help'}, ['redact']),
  stdin: grammar([
    'baseline-path', 'confidence', 'config', 'diagnostics', 'diagnostics-dir', 'disable-rule', 'enable-rule',
    'exit-code', 'experiments', 'gitleaks-ignore-path', 'isolate-rule', 'log-level', 'match-context',
    'max-archive-depth', 'max-decode-depth', 'max-target-megabytes', 'redact', 'regex-engine', 'regexp-engine',
    'report-format', 'report-path', 'report-template', 'set-attr', 'timeout', 'validation-env-vars',
    'validation-max-request', 'validation-max-requests', 'validation-rps', 'validation-rps-rule',
    'validation-status', 'validation-timeout', 'validation-workers',
  ], [
    'help', 'ignore-gitleaks-allow', 'legacy-print', 'no-banner', 'no-color', 'validation', 'validation-debug',
    'validation-extract-empty', 'verbose',
  ], {'c': 'config', 'r': 'report-path', 'f': 'report-format', 'b': 'baseline-path', 'l': 'log-level', 'v': 'verbose', 'i': 'gitleaks-ignore-path', 'h': 'help'}, ['redact']),
};
