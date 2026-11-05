// New-password rules for every form that sets one: Connect's Change
// Password, and the Accounts window's New Account / Set Password. The server
// never sees a password — only a credential derived from it on this machine
// — so it can't enforce any policy; these checks are the only ones applied.

/** Shortest new password the UI accepts, in characters. */
export const MIN_PASSWORD_LENGTH = 8;

/**
 * Why `password` (typed twice: `password` and `confirmation`) can't be used
 * as a new password, or null if it can. Length counts characters (code
 * points), not UTF-16 units or bytes.
 */
export function newPasswordProblem(password, confirmation, minLength = MIN_PASSWORD_LENGTH) {
  const pw = typeof password === "string" ? password : "";
  if (!pw) return "enter a new password";
  if ([...pw].length < minLength) return `use at least ${minLength} characters for the new password`;
  if (!pw.trim()) return "the new password can't be only spaces";
  if (pw !== confirmation) return "the new passwords don't match";
  return null;
}

/**
 * Like newPasswordProblem, for changing your own password: the current one
 * is required, and the new one must differ from it.
 */
export function changePasswordProblem(current, password, confirmation, minLength = MIN_PASSWORD_LENGTH) {
  if (typeof current !== "string" || !current) return "enter your current password";
  const problem = newPasswordProblem(password, confirmation, minLength);
  if (problem) return problem;
  if (password === current) return "the new password is the same as the current one";
  return null;
}
