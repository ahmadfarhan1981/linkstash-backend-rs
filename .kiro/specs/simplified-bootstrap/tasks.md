# Implementation Plan: Simplified Bootstrap

## Overview

Replace the entire `src/cli/` module with a minimal bootstrap command that seeds three hardcoded users directly into SQLite via SeaORM. Delete all old CLI submodules, rewrite `mod.rs` and `bootstrap.rs`, and update `lib.rs` to match. Only files in `src/cli/`, `src/lib.rs`, and `src/main.rs` are touched. No tests — verification is manual (`cargo build`, `cargo run bootstrap`).

## Tasks

- [x] 1. Delete old CLI submodules
  - Delete `src/cli/credential_export.rs`
  - Delete `src/cli/owner.rs`
  - Delete `src/cli/password_management.rs`
  - Delete `src/cli/old/bootstrap.rs` and the `src/cli/old/` directory
  - _Requirements: 1.1, 1.4_

- [x] 2. Rewrite `src/cli/mod.rs` with minimal CLI struct
  - Replace the entire file with a simplified `Cli` struct containing only `--env-file` (global, defaults to `.env`) and an optional `Commands` enum with a single `Bootstrap` variant
  - Implement `execute_command` that matches `Commands::Bootstrap` and calls `bootstrap::run` with `&app_data.connections.auth`
  - Remove all references to deleted submodules (`credential_export`, `owner`, `password_management`, `OwnerCommands`, `LoadCommonPasswordBlocklist`, `Migrate`)
  - _Requirements: 1.1, 1.3, 3.1, 5.1, 5.2, 5.3_

- [x] 3. Implement `src/cli/bootstrap.rs` with direct DB seeding
  - [x] 3.1 Define `SeedUser` struct and `SEED_USERS` constant array
    - Struct fields: `username`, `password`, `is_owner`, `is_system_admin`, `is_role_admin`
    - Three hardcoded users: `owner` (is_owner=true), `admin` (is_system_admin=true), `user` (regular)
    - Passwords: `owner-dev-password-change-me`, `admin-dev-password-change-me`, `user-dev-password-change-me`
    - _Requirements: 2.1, 2.2, 2.3_

  - [x] 3.2 Implement `hash_password` helper function
    - Use `argon2` crate with Argon2id variant and random salt via `rand_core::OsRng`
    - Return the PHC-formatted hash string
    - _Requirements: 2.4_

  - [x] 3.3 Implement `user_exists` helper function
    - Query the `users` table by username using SeaORM `Entity::find().filter()`
    - Return `bool` indicating whether the username is already present
    - _Requirements: 4.1_

  - [x] 3.4 Implement `pub async fn run(db: &DatabaseConnection)`
    - Iterate over `SEED_USERS`, call `user_exists` for each, skip if found (print skip message)
    - For new users: generate UUID, hash password, get current timestamp, build `ActiveModel`, insert via SeaORM
    - Print each user's username and password to console after successful insert
    - Print summary of created vs skipped counts at the end
    - _Requirements: 2.5, 2.6, 3.1, 3.2, 4.1, 4.2, 4.3_

- [x] 4. Update `src/lib.rs`
  - Remove the `seed_test_user` function (already commented out)
  - Simplify `run_cli_commands` — remove the `println!("{:?}", cli.command)` debug line if desired
  - Ensure `pub mod cli` export still works with the rewritten module
  - No other changes needed — `main.rs` flow already delegates to `run_cli_commands` correctly
  - _Requirements: 1.3, 5.2, 5.3_

- [x] 5. Checkpoint — Verify compilation and report
  - Run `cargo build` to verify the project compiles
  - If compile errors exist outside `src/cli/`, `src/lib.rs`, or `src/main.rs`, report them to the developer without fixing
  - _Requirements: 1.2, 1.4, 1.5_

- [x] 6. Final checkpoint — Manual verification instructions
  - Ensure all tasks above are complete, ask the user if questions arise
  - Remind user to verify manually:
    1. Delete `auth.db`, run `cargo run bootstrap` — expect 3 users created
    2. Run `cargo run bootstrap` again — expect 3 users skipped (idempotent)
    3. Run `cargo run` (no subcommand) — expect server starts normally

## Notes

- No tests by design — this is throwaway transitional code, verified manually
- Only `src/cli/`, `src/lib.rs`, and `src/main.rs` are modified; compile errors elsewhere are reported, not fixed
- The bootstrap bypasses all coordinator/provider/store layers intentionally
- Uses `argon2` and `rand_core` crates already in `Cargo.toml`
