// Prompt text for live tool discovery (Plan B Task 2). A TypeScript module, not a .md file, so it is bundled into
// dist and shipped (Plan B ruling S1). The request holds NO repo text (brief; ruling F6): only the need id, its
// category, the language and the package manager, all enum values. The AI never sees the code bundle, README or
// manifests, so a tool name planted in the repo can't reach it, and what it names is only ever a mention-only
// suggestion that pipegen checks live (valid repo, not a look-alike, exists, stats, quality bar) before showing it.

export const CANDIDATES_SYSTEM = [
  'You help pipegen find well-known open-source tools for one kind of CI check.',
  'pipegen only mentions what you name as a suggestion in a report; it never runs it.',
  'Name only tools you are sure exist, with the exact GitHub repository (owner/name) they are developed in.',
  'Answer only with JSON that matches the given schema.',
].join(' ');

/** The fields the AI gets: every one is an enum value (never repo text). */
export interface CandidatesRequest { needId: string; category: string; language: string; packageManager: string }

/** The user message: the enum-only request, then the instructions. */
export function candidatesUser(req: CandidatesRequest, max: number): string {
  const fields = { needId: req.needId, category: req.category, language: req.language, packageManager: req.packageManager };
  return `<need>
${JSON.stringify(fields)}
</need>

Instructions

Suggest up to ${max} widely used, actively maintained open-source tools that perform the "${fields.category}" check for a ${fields.language} project (package manager: ${fields.packageManager}). Put the best first.
- "needId", "category" and "language" repeat the values above.
- "kind": "action" for a GitHub Action, "cli" for a command-line tool, "docker" for a tool used as a container image.
- "name": the tool's usual short name.
- "repo": the GitHub repository it is developed in, exactly "owner/name". No URL, no other host. If you are not sure of the exact repository, leave the tool out.
- "why": one short plain-English sentence on what it checks. No links, no code, no markdown.
Suggest nothing rather than guess.`;
}
