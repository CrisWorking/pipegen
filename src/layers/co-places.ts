// G-COCASE-R2: the CODEOWNERS places and the one name key, in a leaf module (no imports) so deliver, finish, verify and locks share them
// without an import cycle. locks.ts re-exports both.

/** The CODEOWNERS places GitHub reads, in the order it reads them (finish and verify read the same list). */
export const CO_PLACES: readonly string[] = ['.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'];

/**
 * G-COCASE-R2 M3: the key two path names are compared by when one might stand for the other (fail closed): NFKC (fullwidth letters, the
 * long s), then upper case and back to lower case (the dotless i, and every letter toLowerCase alone leaves apart).
 */
export const coKey = (s: string): string => s.normalize('NFKC').toUpperCase().toLowerCase();
