// GitHub login shapes, one leaf for the gate and the CLI (E9, gate-v0.2.2: EMU logins). GitHub's limit is 39 characters for every
// login. An Enterprise Managed User's login is `<normalized name>_<shortcode>`: exactly one underscore, never first or last, the
// shortcode letters and digits. Each pattern checks the length first (a lookahead), so a long text costs one bounded scan.

/** A user login as CODEOWNERS and pipegen's own files write it: letters, digits and inner hyphens, plus an EMU `_<shortcode>`. */
export const STRICT_LOGIN_SOURCE = '(?=[A-Za-z0-9_-]{1,39}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?(?:_[A-Za-z0-9]+)?';
export const STRICT_LOGIN_RE = new RegExp(`^${STRICT_LOGIN_SOURCE}$`);
/**
 * A login (or a user-owned repo's owner) as GitHub's API returns it: the shape pipegen read before E9 (a trailing hyphen of an older
 * account allowed), plus the EMU suffix.
 */
export const API_LOGIN_RE = /^(?=[A-Za-z0-9_-]{1,39}$)[A-Za-z0-9][A-Za-z0-9-]*(?:_[A-Za-z0-9]+)?$/;
