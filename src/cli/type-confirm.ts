// Plan J sub-task J5 (DECISIONS #124; rulings B1, S9, S10, S14): the type question `npx pipegen` asks at a terminal,
// after the local read and before any GitHub call, and the `--type` values. The question shows each service's detected
// type with its evidence and asks "Is this right? (Y/n)"; No asks for each service's type (or "keep"). Repo text (service
// names; the evidence holds only fixed wording and checked paths) is shown through safeText. Only a user cancel (Ctrl+C,
// Esc) is 'cancel'; the CLI then exits 0 with nothing read from GitHub.
import { SERVICE_TYPES, type TypeOverride } from '../read/project-type.js';
import type { Service, ServiceType } from '../types.js';
import { safeText } from '../util/safe-text.js';
import { PromptCancelledError, type Prompter } from './io.js';

export const TYPE_QUESTION = 'Is this right? (Y/n)';
/** Services listed in the question before "and N more" (each still gets its own select after a No). */
const MAX_SERVICES_SHOWN = 25;
const NAME_MAX = 60;
const LINE_MAX = 400;
const KEEP = 'keep';

/** What each type means, for the select's hints. */
const TYPE_HINT: Readonly<Record<ServiceType, string>> = {
  'static-site': 'built into files a host serves; nothing runs as a server',
  library: 'a package other code imports',
  cli: 'a command people run',
  server: 'runs as a server',
  container: 'built into a container image',
};

const typesText = (s: Service): string => {
  const t = s.projectType;
  const types = t === undefined || t.types.length === 0 ? `none of ${SERVICE_TYPES.join(', ')}` : t.types.join(', ');
  return t?.unsure === true ? `${types}, unsure` : types;
};

/** One line per service: `<name>: <types>[, unsure] (<evidence>; …)`, cleaned. */
function serviceLine(s: Service): string {
  const evidence = s.projectType?.evidence ?? [];
  const why = evidence.length === 0 ? '' : ` (${evidence.map((e) => safeText(e, LINE_MAX)).join('; ')})`;
  return safeText(`${safeText(s.name, NAME_MAX)}: ${typesText(s)}${why}`, LINE_MAX);
}

/**
 * Asks whether the detected types are right. [] when they are (or there is no service); the overrides the user picked
 * after a No (a service left on "keep" gets none); 'cancel' when the user cancelled a question. Any other error is thrown.
 */
export async function confirmTypes(prompt: Prompter, services: readonly Service[]): Promise<TypeOverride[] | 'cancel'> {
  if (services.length === 0) return [];
  const shown = services.slice(0, MAX_SERVICES_SHOWN).map((s) => `  ${serviceLine(s)}`);
  const more = services.length - MAX_SERVICES_SHOWN;
  if (more > 0) shown.push(`  …and ${more} more services (set one with --type <service>=<type>)`);
  const message = [`pipegen read ${services.length === 1 ? 'this service' : `these ${services.length} services`} and their types:`, ...shown, TYPE_QUESTION].join('\n');
  try {
    if (await prompt.confirm(message, true)) return [];
    const out: TypeOverride[] = [];
    for (const s of services) {
      const options = [
        { value: KEEP, label: `keep: ${typesText(s)}` },
        ...SERVICE_TYPES.map((t) => ({ value: t, label: t, hint: TYPE_HINT[t] })),
      ];
      const pick = await prompt.select(`The type of ${safeText(s.name, NAME_MAX)}:`, options, KEEP);
      if (pick !== KEEP && (SERVICE_TYPES as readonly string[]).includes(pick)) out.push({ service: s.name, type: pick as ServiceType });
    }
    return out;
  } catch (e) {
    if (e instanceof PromptCancelledError) return 'cancel';
    throw e;
  }
}

/**
 * The `--type` values (ruling S10): `<type>` (the repo's only service) or `<service>=<type>` (the type is after the
 * last "="). Returns the overrides, or the message for the first value that isn't one. Whether the service exists,
 * whether a bare type fits the repo and whether a service is named twice is checked against the services read
 * (applyTypeOverrides).
 */
export function parseTypeFlags(values: readonly string[]): TypeOverride[] | string {
  const out: TypeOverride[] = [];
  for (const v of values) {
    const eq = v.lastIndexOf('=');
    const service = eq < 0 ? null : v.slice(0, eq);
    const type = eq < 0 ? v : v.slice(eq + 1);
    if (!(SERVICE_TYPES as readonly string[]).includes(type)) {
      return `Unknown type "${safeText(type, 40)}" in --type ${safeText(v, 100)}: use --type <type> or --type <service>=<type>, with one of ${SERVICE_TYPES.join(', ')}.`;
    }
    if (service !== null && service.trim() === '') return `--type ${safeText(v, 100)} has no service name before "=": use --type <service>=<type>.`;
    out.push({ service, type: type as ServiceType });
  }
  return out;
}
