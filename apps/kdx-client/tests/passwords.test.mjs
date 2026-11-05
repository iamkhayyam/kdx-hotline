// New-password rules (passwords.js): the only password policy there is,
// since the server only ever sees a credential derived from the password.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MIN_PASSWORD_LENGTH,
  newPasswordProblem,
  changePasswordProblem,
} from "../dist/js/passwords.js";

test("a new password needs the minimum length and a matching confirmation", () => {
  const ok = "x".repeat(MIN_PASSWORD_LENGTH);
  assert.equal(newPasswordProblem(ok, ok), null);
  assert.match(newPasswordProblem("", ""), /enter a new password/);
  assert.match(newPasswordProblem(undefined, undefined), /enter a new password/);
  const short = "x".repeat(MIN_PASSWORD_LENGTH - 1);
  assert.match(newPasswordProblem(short, short), /at least 8 characters/);
  assert.match(newPasswordProblem(ok, ok + "y"), /don't match/);
  assert.match(newPasswordProblem(ok, undefined), /don't match/);
  const blank = " ".repeat(MIN_PASSWORD_LENGTH);
  assert.match(newPasswordProblem(blank, blank), /only spaces/);
});

test("length counts characters, not UTF-16 units", () => {
  // Four astral characters are eight UTF-16 units but only four characters.
  const emoji = "🔑🔑🔑🔑";
  assert.equal(emoji.length, 8);
  assert.match(newPasswordProblem(emoji, emoji), /at least/);
  const accented = "é".repeat(MIN_PASSWORD_LENGTH);
  assert.equal(newPasswordProblem(accented, accented), null);
  assert.equal(newPasswordProblem("abc", "abc", 3), null, "custom minimum");
});

test("changing your own password needs the current one and a different new one", () => {
  const next = "correct horse";
  assert.equal(changePasswordProblem("old secret", next, next), null);
  assert.match(changePasswordProblem("", next, next), /current password/);
  assert.match(changePasswordProblem(null, next, next), /current password/);
  assert.match(changePasswordProblem("old secret", next, "typo"), /don't match/);
  assert.match(changePasswordProblem(next, next, next), /same as the current/);
  assert.match(changePasswordProblem("old secret", "short", "short"), /at least/);
});
