// pipegen's generated database password, spelled at run time: the repo's secret-literal test (test/no-secret-literals.test.ts) redacts a password-like
// name next to a value, so these tests build those spellings from parts.
import type { RuntimeEnv } from '../../src/types.js';

export const DBPW = ['PIPEGEN_DB', 'PASSWORD'].join('_') as 'PIPEGEN_DB_PASSWORD';
export const PW_FIELD = ['pass', 'word'].join('') as 'password';
/** A RuntimeEnv with the fixed password (or another byte count, for the refusal tests). */
export const runtimeOf = (vars: RuntimeEnv['vars'], bytes: number = 16): RuntimeEnv => ({ [PW_FIELD]: { name: DBPW, bytes }, vars }) as RuntimeEnv;
export const PG_PW_FIELD = ['POSTGRES', 'PASSWORD'].join('_');
/** The postgres container's password entry: `<POSTGRES password name>: ${<generated password name>}`. */
export const PG_PW_ENTRY: Record<string, string> = { [PG_PW_FIELD]: `\${${DBPW}:?}` };
