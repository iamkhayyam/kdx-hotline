//! `sqlx::migrate!` embeds the migrations directory at compile time, but
//! cargo only re-runs the macro when a Rust source changes. Tell cargo to
//! rebuild this crate whenever a migration is added or edited, so a new
//! `NNNN_*.sql` file can never be silently left out of the binary.
fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
