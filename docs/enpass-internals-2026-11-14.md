# Enpass CLI and installed application investigation

Inspected on 2026-11-14. Scope: CLI source, shipped application structure,
TOTP representation and concrete editing failures. No personal vault was opened
or changed. Native application acceptance and cloud synchronization were not tested.

## Repository

The existing fork is https://github.com/ozio/enpass-cli, parent
https://github.com/hazcod/enpass-cli. The local checkout was clean on `master` at
`a226269224ff07a808636b8db53cb6003659b830`. Upstream `620b655` contains the same
vault-name fix under a merged commit, so there was no source change to import.
The Go module path stays upstream-compatible for existing library consumers.

`cmd/enpasscli/main.go` implements the CLI. `pkg/enpass/vault.go` opens the
SQLCipher database and queries entries. `card.go` decrypts password fields.
`crypto.go` encrypts fields; `write.go` writes SQL directly. This is not an
RPC client for the native application and does not notify its in-memory model.
`pkg/unlock` contains optional PIN/biometric key storage. The separate local
`enpass-mcp` uses a pinned library revision and remains read-only; these CLI
changes do not update its capabilities or installed binary.

## Shipped application observations

Target: `/Applications/Enpass.app/Contents/MacOS/Enpass`, version 6.12.8.
SHA-256: `4deec17e852e5d1500806eb384f414f6c2b07842c2e3144a5603a3ef1ae7f6a4`.
REA Mach-O inspection selected arm64, container slice offset 102039552,
UUID `275C0651-A5E8-33E6-AF6C-6DC5F18D9768`; the universal binary also contains
x86_64. Its 62 library loads include Cocoa, WebKit, Security and
LocalAuthentication. This establishes linked dependencies, not execution.

REA Evidence:
- Mach-O inventory: `ev_ead9bcf0a095a6a361299dadc407a3985f10dd36c26e487eaf9670b254e900cd`.
- Summary: `ev_43bab197465aa0035cb8af0b24e6e185d46c6ba408958ca69605bb0a7051de34`.
- Dependency view: `ev_e0f3275b6b92ad06653fd9bd5c87ffce939b21bfe9440942afb56cdab20c1e71`.

The following are ordinary shell/Python static observations from the arm64
slice, with offsets relative to the entire universal file:

| Offset | Observation | What it establishes |
| --- | --- | --- |
| `0x8d58e34` | `get_totp` | A command-name string exists; handler behavior is unverified. |
| `0x8d58e93` | `add_or_update_totp_field` | A candidate native TOTP write command exists; its transport, authorization and schema are unresolved. |
| `0x8d8cecf` | SQL selects `item_field_uid,orde,type,value`, filtering active fields including `totp`, `password`, `ccTxnpassword` | Field identifiers, order and deletion state matter to the native reader. |
| `0x8d93d2e` | Password audit SQL reads `hash`, `initial`, `excluded`, and both password types | Password auditing has metadata beyond ciphertext; its writer remains unresolved. |
| `0x9e1077d` | Embedded QML imports QtQuick, QtQuick.Controls and Enpass modules; declares `totpSecret`; calls `gUtilityWorker.makeTotpofValue(totpSecret)` | The shipped UI contains a TOTP renderer with a one-second timer and a period returned by native code (default 30). The renderer is actual packaged source text, not decompiler reconstruction. |
| `0xaffc1d4` | `makeTotpofValue` | The corresponding method name is present. |

The checked-in synthetic SQLCipher fixture independently confirms the `item`
and `itemfield` schema, including `item_field_uid`, `orde`, `history`,
`updated_at`, `value_updated_at`, and `algo_version`. Existing library code
uses a 44-byte per-item AES key/nonce and the UUID as GCM associated data for
password fields. The library treats TOTP as a plain field inside the encrypted
database. This is a source/fixture observation; storage compatibility with all
current native formats has not been established.

The REA native-procedure search could not run: no Ghidra/IDA/Kuna provider was
configured and the configured Hopper executable was absent. No analysis engine
or application was installed or modified. Symbol/string presence does not prove
that a handler is reachable or safe to invoke.

Local, ignored evidence is in `.work/enpass-research/rea-evidence.json` and
`.work/enpass-research/static-strings.json`. The REA session was closed after export.

## First implementation

- Create/update a TOTP field with a bare base32 secret or `otpauth://totp` URI.
  Validation accepts SHA1/SHA256/SHA512, 6–8 digits, positive integral periods;
  it rejects HOTP, duplicate/empty recognized parameters and malformed values.
  Invalid data is rejected before writing; validation errors omit the secret.
- Read either the new password or the new TOTP value from bounded stdin input,
  excluding the final line ending. No secret is written to temporary files.
- Parse flags before or after commands/filters, respecting `--` literal operands.
- Explicitly clear login, password, URL, notes or TOTP. Empty `-login=`, `-url=`,
  `-notes=` and `-totp=` are explicit clears in edit mode.
- Assign inserted fields an entry-local ID, label, order and timestamps.
  Edits update field/item timestamps and do not revive tombstones.
- Refuse ambiguous fields instead of overwriting every matching type. Password
  key replacement is also refused when another nonempty password ciphertext
  (including deleted fields), unknown sensitive fields, or opaque history would be invalidated. All changes
  to the entry roll back on refusal. This protects data; it does not implement
  multi-password editing or password-history migration.
- Reject missing entries, empty patches and empty edit selectors. Missing or
  malformed password keys now return errors instead of causing a slice panic.
- Noninteractive writes requiring confirmation fail unless `-force` is given.

Verification uses the repository's public synthetic fixture only: library
round trips, atomic rejection, multi-password preservation, tombstones, explicit
clearing, parameter validation, command parsing, stdin bounds and actual CLI
subprocess create/edit/list/show operations. Existing write tests now fail
instead of skipping when their fixture cannot be opened.

## Remaining compatibility work

1. Native round trip in a separate disposable vault: inspect how the current
   app writes a new TOTP and confirm it can open CLI-created entries. Verify
   field ID allocation, templates, labels, category IDs and synchronization.
2. Trace the candidate native `add_or_update_totp_field` command and browser
   extension authentication. An authenticated native writer may be preferable
   to direct SQL for synchronization and audit metadata.
3. Reconstruct all encrypted field types, item-key rotation, password-history
   encoding and audit metadata before enabling writes to complex password items.
4. Add explicit UUID/field-ID selectors and code-only TOTP output, then consider
   exposing verified operations through the separate MCP project.

Until the native round trip is verified, use a disposable or backed-up offline
vault with the Enpass app closed. Direct database writes have not been proven
compatible with native caches, cloud merge rules, or every schema version.
