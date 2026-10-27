#!/bin/sh
# Everything a change must pass: php -l on every PHP file, sh -n on the
# shell scripts, and the test suite. Usage: sh tests/check.sh
set -u
cd "$(dirname "$0")/.."
rc=0
for f in $(find src tests -name '*.php' -o -name '*.inc'); do
	php -l "$f" >/dev/null || { echo "php -l failed: $f"; rc=1; }
done
for f in install.sh uninstall.sh src/usr/local/etc/rc.d/webauthn_hook.sh tests/check.sh tests/mutate.sh; do
	sh -n "$f" || { echo "sh -n failed: $f"; rc=1; }
done
echo "php -l and sh -n: $([ $rc = 0 ] && echo ok || echo FAILED)"
php tests/run.php | tail -1
php tests/run.php >/dev/null || rc=1
exit $rc
