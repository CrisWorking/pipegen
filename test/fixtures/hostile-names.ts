// Hostile strings built in code (never committed as raw bytes).
const ESC = '\x1b';

export const hostileNames: Record<string, string> = {
  ansiColour: `${ESC}[31mred${ESC}[0m-app`,
  screenClear: `${ESC}[2J${ESC}[Happ`,
  osc8Link: `${ESC}]8;;https://evil.example/x${ESC}\\click me${ESC}]8;;${ESC}\\`,
  osc8LinkBel: `${ESC}]8;;https://evil.example/x\x07click me${ESC}]8;;\x07`,
  bidiOverride: `app\u202efdp.exe`,
  bidiIsolates: `\u2066app\u2069\u200e\u200f\u061c`,
  nulAndCr: 'app\x00name\rOVERWRITTEN',
  newlines: 'line1\nline2\r\nline3\ttab',
  mention: 'thanks @octocat and @org/team',
  htmlTag: '<script>alert(1)</script><img src=x onerror=alert(1)>',
  markdownLink: '[click](https://evil.example) ![img](https://evil.example/a.png)',
  veryLong: 'a'.repeat(5000),
};
