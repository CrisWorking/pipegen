import { readFileSync } from 'node:fs';

// Minimal placeholder entry point; a later task replaces it with the real CLI.
const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version: string };
console.log(`pipegen ${pkg.version}`);
console.log('commands coming soon');
