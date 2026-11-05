//! Server-wide input and resource caps.
//!
//! Every length a client controls is bounded here, in one place, so a single
//! oversized field can't blow up a broadcast, a list reply, the history log,
//! or the database. Handlers reject an over-limit request with an `Error`
//! reply (never by dropping the connection) unless the field is pre-auth.
//!
//! Lengths are in bytes of UTF-8, not characters.

/// Account username (login name). Checked before any DB lookup at login.
pub const MAX_USERNAME_LEN: usize = 64;
/// Display nick set via `SetIdentity`.
pub const MAX_NICK_LEN: usize = 64;
/// Free-text description set via `SetIdentity`.
pub const MAX_DESCRIPTION_LEN: usize = 512;
/// One chat line (room chat or private message).
pub const MAX_CHAT_TEXT_LEN: usize = 4096;
/// Room topic.
pub const MAX_TOPIC_LEN: usize = 512;
/// Free-text admin-supplied reason (kick/ban reason, IP rule note).
pub const MAX_REASON_LEN: usize = 512;
/// Admin broadcast text.
pub const MAX_BROADCAST_LEN: usize = 4096;
/// News post subject.
pub const MAX_NEWS_SUBJECT_LEN: usize = 256;
/// News post body.
pub const MAX_NEWS_BODY_LEN: usize = 32 * 1024;
/// Newsgroup / role / room display names.
pub const MAX_NAME_LEN: usize = 64;
/// Newsgroup / role descriptions.
pub const MAX_LONG_DESCRIPTION_LEN: usize = 1024;
/// One file or folder name in the virtual tree.
pub const MAX_FILE_NAME_LEN: usize = 255;
/// A full virtual path in a request.
pub const MAX_PATH_LEN: usize = 4096;
/// Maximum folder nesting depth in the virtual tree.
pub const MAX_TREE_DEPTH: usize = 64;
/// File-search query string.
pub const MAX_SEARCH_QUERY_LEN: usize = 256;
/// Server name (settings).
pub const MAX_SERVER_NAME_LEN: usize = 64;
/// Server description (settings).
pub const MAX_SERVER_DESCRIPTION_LEN: usize = 1024;
/// Login greeting / agreement text (settings).
pub const MAX_GREETING_LEN: usize = 8 * 1024;
/// History log: actor column, truncated at record time.
pub const MAX_HISTORY_ACTOR_LEN: usize = 64;
/// History log: detail column, truncated at record time.
pub const MAX_HISTORY_DETAIL_LEN: usize = 512;

/// Rooms a single connection may be joined to at once.
pub const MAX_JOINED_ROOMS_PER_CONNECTION: usize = 32;
/// Total chat rooms (public + private) the server will hold.
pub const MAX_ROOMS: usize = 1024;
/// Entries sent in one `FileListResponse` (its count field is a `u16`).
pub const MAX_FILE_LIST_ENTRIES: usize = 10_000;

/// Truncate `s` to at most `max` bytes on a UTF-8 character boundary.
pub fn truncate_utf8(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// `Err(message)` if `value` is longer than `max` bytes; the message names
/// the field so the client can show something actionable.
pub fn check_len(field: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        Err(format!("{field} too long ({} bytes, max {max})", value.len()))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate_utf8("hello", 10), "hello");
        assert_eq!(truncate_utf8("hello", 3), "hel");
        // "é" is two bytes; cutting at 1 must back off to 0.
        assert_eq!(truncate_utf8("é", 1), "");
        assert_eq!(truncate_utf8("aé", 2), "a");
    }

    #[test]
    fn check_len_names_the_field() {
        assert!(check_len("nick", "abc", 3).is_ok());
        let err = check_len("nick", "abcd", 3).unwrap_err();
        assert!(err.contains("nick"));
    }
}
