// Built by the redact test with tsup into <temp package>/dist/cli/ (an installed-package layout, like
// dist/cli/main.js) to prove the bundled code finds <package>/data/gitleaks-bundle.toml, and fails closed.
import { secretScanConfigPath } from '../../src/ai/secret-scan-config.js';

console.log(secretScanConfigPath());
