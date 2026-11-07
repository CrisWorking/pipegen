// G15a round 5 (b3, P-4): the reviewed Automation Framework plan of the nightly ZAP active scan. A constant: no AI value, no repo text.
// Taken from the plan the real reports were captured with (test/fixtures/zap/plans/af-active-capture.yaml, README there), with the
// target replaced by the AF's own environment substitution: the run step passes the URL of the running app (a `local-url` slot,
// slots.ts: http://localhost or http://127.0.0.1 with a port) into the container as ZAP_ACTIVE_TARGET_ENV, and nothing else.
// Round 6: run nightly by the reviewed entry zap-af-active (data/reviewed-tools.yml; tool-flags.ts holds this text as its pinned config), in
// its own lane beside nuclei (dast-handoff.ts zapActiveSpec), scrubbed to SARIF for code scanning.

/** The container env variable the plan reads the target from (`${…}` is the AF's substitution, measured on the pinned image). */
export const ZAP_ACTIVE_TARGET_ENV = 'PIPEGEN_ZAP_TARGET';
/** Where the plan sits and where the AF writes its report, inside the container's work folder (zap.sh resolves a relative plan path against /zap, not the cwd). */
export const ZAP_ACTIVE_WORK = '/zap/wrk';
export const ZAP_ACTIVE_PLAN_FILE = 'zap-active.yaml';
export const ZAP_ACTIVE_REPORT = 'zap-active.json';
/**
 * The command as the renderer writes it: `-autorun` the plan by its absolute path (the pinned config flag goes first), `-cmd` (no UI),
 * `-silent` (no add-on update, no call home). Round 6 measured this order on the pinned image (exit 0, the report written; G15a report).
 */
export const ZAP_ACTIVE_COMMAND = Object.freeze(['zap.sh', '-autorun', `${ZAP_ACTIVE_WORK}/${ZAP_ACTIVE_PLAN_FILE}`, '-cmd', '-silent'] as const);
/**
 * The scan policy, reviewed: ZAP's default rules at their default strength and threshold (`medium`), none turned off or down; at most
 * 5 minutes per rule and 30 for the whole active scan. The AF exits 0 with alerts and 1 on a plan error (`failOnError`), so the run step
 * takes only exit 0 with a report (no findings exit code).
 */
export const ZAP_ACTIVE_POLICY = Object.freeze({ defaultStrength: 'medium', defaultThreshold: 'medium', maxRuleDurationInMins: 5, maxScanDurationInMins: 30 } as const);

/** The plan's own time limits of the spider and the passive wait, in minutes (the active scan's is ZAP_ACTIVE_POLICY.maxScanDurationInMins). */
export const ZAP_ACTIVE_SPIDER_MINUTES = 5;
export const ZAP_ACTIVE_PASSIVE_MINUTES = 5;
/** The image pull and the app start before the scan, at most (measured: under 2 minutes on a small app). */
export const ZAP_ACTIVE_START_MINUTES = 5;
/**
 * G15a-R8 spec 1: the most one nightly AF run can take by the plan's own limits: spider, passive wait, active scan and the start (45). The job's
 * timeout (dast-handoff.ts ZAP_ACTIVE_JOB_MINUTES, 60) only guards a hang; the estimate shows this ceiling beside its 5-minute headline.
 */
export const ZAP_ACTIVE_CEILING_MINUTES = ZAP_ACTIVE_SPIDER_MINUTES + ZAP_ACTIVE_PASSIVE_MINUTES + ZAP_ACTIVE_POLICY.maxScanDurationInMins + ZAP_ACTIVE_START_MINUTES;
const T = `\${${ZAP_ACTIVE_TARGET_ENV}}`;
/**
 * G15a-R7 sec 4: the context is the target's origin only. ZAP matches a context regex against the whole URL (Java regex). `\Q…\E` quotes the
 * target (its dots are literal; a local URL holds no `\E`), and after it comes nothing or a path: never `:30001` (a longer port), `@host` (another
 * authority) or `.evil` (a longer host). The AF also adds each context URL as an include of its own, `<url>.*` unquoted (measured on the pinned
 * image: with the include alone, a link to http://<host>:8080 from the target http://<host>:808 was still actively scanned), so every URL outside
 * the origin is excluded as well, and an exclude wins over an include. Re-measured on the pinned image (G15a report, round 7): the fixture
 * target gives the same alert types, and the other origin is no longer scanned.
 */
const ORIGIN = `\\Q${T}\\E(?:/.*)?`;
/** The plan text the run step writes into the work folder. Spider and passive wait 5 minutes at most each; the report is the traditional-json template the gate reads (gate/src/zap.ts). */
export const ZAP_ACTIVE_PLAN = [
  'env:',
  '  contexts:',
  '    - name: pipegen',
  '      urls:',
  `        - "${T}"`,
  '      includePaths:',
  `        - '${ORIGIN}'`,
  '      excludePaths:',
  `        - '(?!${ORIGIN}$).*'`,
  '  parameters:',
  '    failOnError: true',
  '    failOnWarning: false',
  '    progressToStdout: true',
  'jobs:',
  '  - type: passiveScan-config',
  '    parameters:',
  '      maxAlertsPerRule: 10',
  '      enableTags: false',
  '  - type: spider',
  '    parameters:',
  '      context: pipegen',
  `      url: "${T}"`,
  `      maxDuration: ${ZAP_ACTIVE_SPIDER_MINUTES}`,
  '  - type: passiveScan-wait',
  '    parameters:',
  `      maxDuration: ${ZAP_ACTIVE_PASSIVE_MINUTES}`,
  '  - type: activeScan',
  '    parameters:',
  '      context: pipegen',
  `      maxRuleDurationInMins: ${ZAP_ACTIVE_POLICY.maxRuleDurationInMins}`,
  `      maxScanDurationInMins: ${ZAP_ACTIVE_POLICY.maxScanDurationInMins}`,
  '    policyDefinition:',
  `      defaultStrength: ${ZAP_ACTIVE_POLICY.defaultStrength}`,
  `      defaultThreshold: ${ZAP_ACTIVE_POLICY.defaultThreshold}`,
  '  - type: report',
  '    parameters:',
  '      template: traditional-json',
  `      reportDir: ${ZAP_ACTIVE_WORK}`,
  `      reportFile: ${ZAP_ACTIVE_REPORT}`,
  '      reportTitle: pipegen ZAP active scan',
  '',
].join('\n');
