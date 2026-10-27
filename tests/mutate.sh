#!/bin/sh
# Mutation check for the test suite: sh tests/mutate.sh
# Makes small security-relevant breakages in src/ one at a time and
# checks that tests/run.php fails for each ("killed"). Every file is
# restored afterwards. A mutation whose pattern no longer matches the
# code is reported as NOT APPLIED (update it after a refactor).
set -u
cd "$(dirname "$0")/.."
trap 'for f in src/usr/local/pkg/webauthn/*.bak; do [ -e "$f" ] && mv "$f" "${f%.bak}"; done' EXIT INT TERM
D=src/usr/local/pkg/webauthn
m() { # file, perl substitution, label
	cp "$1" "$1.bak"; perl -0pi -e "$2" "$1"
	if cmp -s "$1" "$1.bak"; then echo "NOT APPLIED: $3"; else
	if php tests/run.php >/dev/null 2>&1; then echo "SURVIVED: $3"; else echo "killed:   $3"; fi; fi
	mv "$1.bak" "$1"
}
m $D/webauthn_lib.inc 's/if \(!\(\$ad\[.flags.\] & WEBAUTHN_FLAG_UP\)\)/if (false)/' 'UP flag check'
m $D/webauthn_lib.inc 's/\$ad\[.sign_count.\] <= \$stored/\$ad["sign_count"] < \$stored/' 'lib counter <= to <'
m $D/webauthn.inc 's/\(\$count != 0 \|\| \$stored != 0\) && \$count <= \$stored/false/' 'advance counter'
m $D/webauthn_lib.inc 's/(function webauthn_check_auth_data.*?)if \(!hash_equals\(hash\(.sha256., \$rp_id, true\), \$ad\[.rp_id_hash.\]\)\)/$1if (false)/s' 'auth data rp hash'
m $D/webauthn_lib.inc 's/\$origin === .. \|\| !in_array\(\$origin, \$allowed, true\)/false/' 'origin check'
m $D/webauthn_lib.inc 's/\|\| !hash_equals\(webauthn_b64url_encode\(\$challenge\), \$cd\[.challenge.\]\)//' 'challenge compare'
m $D/webauthn_lib.inc 's/return openssl_verify\(\$data, \$sig, \$key, OPENSSL_ALGO_SHA256\) === 1;/return true;/' 'openssl verify'
m $D/webauthn.inc 's/if \(\$source\[.via_proxy.\] \|\| \$source\[.proxy_headers.\] \|\| \$source\[.peer.\] === ..\) \{\n\t\treturn false;/if (\$source["peer"] === "") {\n\t\treturn false;/' 'trusted net ignores proxy'
m $D/webauthn.inc "s/return empty\(\\\$settings\['enforce'\]\) \? 'skip' : 'deny';/return 'skip';/" 'enforce deny'
m $D/webauthn.inc 's/\$used === null \|\| isset\(\$used\[\$nonce\]\) \|\| count\(\$used\) >= WEBAUTHN_MAX_LIVE_NONCES\) \{\n\t\t\treturn null;/\$used === null) {\n\t\t\treturn null;/' 'nonce reuse'
m $D/webauthn.inc 's/hash_equals\(\$state\[.sid.\], webauthn_session_sid\(\)\)/true/' 'sid binding'
m $D/webauthn.inc 's/\$now - \$time <= WEBAUTHN_VERIFIED_MAX_AGE/true/' 'verified max age'
m $D/webauthn.inc "s/return \['user' => \\\$user, 'method' => 'webauthn', 'credential' => \(string\)\\\$cred\['id'\]/return ['user' => \\\$user, 'method' => 'webauthn', 'credential' => 'x'/" 'verified state credential'
m $D/webauthn.inc 's/!isset\(\$revoked\[\(string\)\(\$c\[.id.\] \?\? ..\)\]\);/true;/' 'revocation filter'
m $D/webauthn.inc 's/if \(webauthn_revoked_ids\(\) === null\) \{/if (false) {/' 'damaged revoked list'
m $D/webauthn.inc 's/!webauthn_orphaned\(\$c\)\)\)/true))/' 'orphan check'
m $D/webauthn.inc 's/return !empty\(webauthn_case_variant_credentials\(\$user\)\);/return false;/' 'case variants'
m $D/webauthn.inc 's/hash_equals\(webauthn_challenge_mac\(\$purpose, \$username, \$payload\), substr\(\$challenge, 20\)\)/true/' 'challenge mac'
m $D/webauthn.inc 's/\$expires < \$now \|\| //' 'challenge expiry'
m $D/gate.inc "s/unset\(\\\$_SESSION\['webauthn'\], \\\$_SESSION\['page-match'\]\);\n\n\tif \(isAjax/unset(\\\$_SESSION['webauthn']);\n\n\tif (isAjax/" 'page-match drop'
m $D/gate.inc "s/if \(\\\$decision == 'verified'\) \{/if (\\\$decision == 'verified' || \\\$decision == 'deny') {/" 'gate deny'
m $D/gate.inc "s/return in_array\(\\\$status, \['verified', 'skip'\], true\);/return true;/" 'cached privileges'
m $D/gate.inc 's/if \(webauthn_is_login_post\(\) && isset\(\$_SESSION\[.webauthn.\]\)\) \{/if (false) {/' 'login resets'
m $D/gate.inc 's/if \(\$failures >= WEBAUTHN_MAX_FAILURES\) \{/if (false) {/' 'max failures'
m $D/gate.inc 's/if \(\(\$cred\[.rp_id.\] \?\? ..\) !== webauthn_rp_id\(\$settings\)\)/if (false)/' 'cred rp_id'
m $D/xmlrpc_guard.inc 's/if \(\$source\[.via_proxy.\] \|\| \$source\[.proxy_headers.\]\) \{/if (false) {/' 'xmlrpc proxy'
m $D/xmlrpc_guard.inc 's/return \$source\[.peer.\] === .. \|\| !webauthn_ip_in_list/return \$source["peer"] === "" \&\& !webauthn_ip_in_list/' 'xmlrpc peers'
m $D/cbor.inc 's/if \(\$offset \+ \$arg > \$len\) \{/if (false) {/' 'cbor string truncation'
m $D/cbor.inc 's/if \(array_key_exists\(\$k, \$out\)\) \{/if (false) {/' 'cbor duplicate keys'
m $D/cbor.inc 's/if \(\$depth > 16\)/if (\$depth > 100)/' 'cbor depth'
m $D/cbor.inc 's/return WEBAUTHN_CBOR_TEXT_KEY_PREFIX . \$k;/return \$k;/' 'cbor text keys'
m $D/webauthn_lib.inc 's/if \(\$offset != strlen\(\$raw\)\) \{/if (false) {/' 'authdata trailing'
m $D/webauthn_lib.inc 's/if \(!empty\(\$cd\[.crossOrigin.\]\)\) \{/if (false) {/' 'crossOrigin'
m $D/webauthn_lib.inc 's/if \(\(\$cd\[.type.\] \?\? null\) !== \$type\) \{/if (false) {/' 'ceremony type'
m $D/webauthn_lib.inc 's/if \(\$require_uv && !\(\$ad\[.flags.\] & WEBAUTHN_FLAG_UV\)\) \{/if (false) {/' 'uv required'
m $D/hook.inc "s/require_once\('\/usr\/local\/pkg\/webauthn\/gate.inc'\);\\\\n\" \.\n\t\t\t    \"webauthn_gate/\@include('\/usr\/local\/pkg\/webauthn\/gate.inc');\\\\n\" .\n\t\t\t    \"webauthn_gate/" 'hook fail-closed'
