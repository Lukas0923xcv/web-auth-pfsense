# Tests

Plain PHP, no Composer: `php tests/run.php [name filter]`.
`sh tests/check.sh` also runs `php -l` on every PHP file and `sh -n` on
the shell scripts. `sh tests/mutate.sh` breaks security checks in `src/`
one at a time (and restores them) to show the suite notices each one.

This folder is never installed: `install.sh` only copies from `src/`.

- `lib/stubs.php` stands in for the pfSense functions the package calls
  (config read/write, sessions, notices). `config_read_file()` and
  `parse_xml_config()` return what the last `write_config()` saved.
- `lib/fixtures.php` has a CBOR encoder and software authenticators
  (ES256, RS256, Ed25519) that produce real signatures.
- Code that ends the request with `exit` (`webauthn_gate()`,
  `webauthn_xmlrpc_guard()`) runs in a child process (`lib/child.php`).
- `stubs-inc/` replaces pfSense's include files so `hook.php status`
  can run here.
