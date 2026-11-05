// Connecting from an Address Book bookmark (pure logic).
//
// A bookmark's password lives in the OS keychain and is read by the Rust
// side at login, never by the webview. Submitting the login automatically
// only makes sense when one is saved: without it the password is empty, the
// login is certain to fail, and it burns one of the server's free attempts
// before it starts throttling this address + login.

/** The Connect-window UI commands for connecting via bookmark `b`, as
 * [action, args] pairs: fill the form, then submit only if a password is
 * saved — otherwise the Connect window asks for one. */
export function bookmarkConnectCommands(b) {
  const fill = {
    host: b.host,
    port: b.port,
    login: b.login,
    bookmarkId: b.id,
    hasSecret: !!b.hasSecret,
  };
  if (b.hasSecret) return [["fill", fill], ["submit", {}]];
  return [["fill", { ...fill, askPassword: true }]];
}

/** May an automatic submit go ahead? Only with a typed password or a saved
 * one (the bookmark id the Rust side reads it by). */
export function canAutoSubmit({ password, bookmarkId }) {
  return (typeof password === "string" && password.length > 0) || !!bookmarkId;
}
