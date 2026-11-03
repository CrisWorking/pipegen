Real reports captured on 2026-11-02 from one test file (nested describes, one pass, one failure, one skip, a test named `__proto__`):
- vitest-5.0.5.xml: vitest 5.0.5, `--reporter=junit`.
- jest-junit-17.0.0-default.xml: jest 30.5.2 with jest-junit 17.0.0, default options.
- jest-junit-17.0.0-configured.xml: the same, with classNameTemplate `{classname}`, titleTemplate `{title}`, ancestorSeparator ` > `, addFileAttribute `true`.
Edits: the hostname is replaced, and the stack-frame lines (`    at ...`, which held local paths) of the failure text are removed.
- jest-junit-17.0.0-todo-and-hook-error.xml: jest-junit 17.0.0 (configured as above) on a file with a `test.todo` and a failing `afterAll`. jest-junit writes the todo as a plain test case and the hook failure as an extra failing case, and leaves both out of the `tests` count (tests="4", six cases). Edit: the stack paths in the hook failure are removed.
