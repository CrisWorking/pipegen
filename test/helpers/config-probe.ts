// Built by the redact test with tsup into <root>/<dir>/cli/, the same depth as dist/cli/main.js,
// to prove the bundled code finds data/gitleaks-bundle.toml.
import { gitleaksConfigPath } from '../../src/ai/gitleaks-config.js';

console.log(gitleaksConfigPath());
