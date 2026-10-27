<?php
/* webauthn_lib.inc: registration and assertion verification. */

/* Register $auth, returning the stored-credential shape webauthn_verify_assertion() takes. */
function lib_credential(TestAuthenticator $auth, bool $uv = false): array {
	$ch = random_bytes(36);
	[$cd, $att] = $auth->register($ch, T_RP, T_ORIGIN);
	$reg = webauthn_verify_registration($cd, $att, $ch, T_RP, [T_ORIGIN], $uv);
	t_eq($auth->id, $reg['credential_id']);
	return ['alg' => $reg['alg'], 'pem' => $reg['pem'], 'sign_count' => $reg['sign_count']];
}

function lib_verify(array $cred, array $a, string $ch, array $o = []): int {
	return webauthn_verify_assertion($cred, $a['client_data'], $a['authenticator_data'], $a['signature'], $ch,
	    $o['rp_id'] ?? T_RP, $o['origins'] ?? [T_ORIGIN], $o['uv'] ?? false, $info);
}

function test_lib_valid_assertion_accepted_all_algorithms(): void {
	foreach ([WEBAUTHN_ALG_ES256, WEBAUTHN_ALG_RS256, WEBAUTHN_ALG_EDDSA] as $alg) {
		$auth = new TestAuthenticator($alg);
		$cred = lib_credential($auth);
		t_eq($alg, $cred['alg']);
		$ch = random_bytes(36);
		t_eq(1, lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN), $ch), "alg {$alg}");
	}
}

function test_lib_assertion_reports_uv_flag(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	$a = $auth->assert($ch, T_RP, T_ORIGIN);
	webauthn_verify_assertion($cred, $a['client_data'], $a['authenticator_data'], $a['signature'], $ch, T_RP, [T_ORIGIN], true, $info);
	t_eq(true, $info['uv']);
	$a = $auth->assert($ch, T_RP, T_ORIGIN, ['flags' => WEBAUTHN_FLAG_UP]);
	webauthn_verify_assertion($cred, $a['client_data'], $a['authenticator_data'], $a['signature'], $ch, T_RP, [T_ORIGIN], false, $info);
	t_eq(false, $info['uv']);
}

function test_lib_wrong_signature_rejected(): void {
	foreach ([WEBAUTHN_ALG_ES256, WEBAUTHN_ALG_RS256, WEBAUTHN_ALG_EDDSA] as $alg) {
		$auth = new TestAuthenticator($alg);
		$cred = lib_credential($auth);
		$ch = random_bytes(36);
		$a = $auth->assert($ch, T_RP, T_ORIGIN);
		$bad = $a;
		$bad['signature'][10] = chr(ord($bad['signature'][10]) ^ 1);
		t_throws(fn() => lib_verify($cred, $bad, $ch), WebAuthnException::class, 'Signature verification failed');
		/* Signed by another key. */
		$other = new TestAuthenticator($alg);
		t_throws(fn() => lib_verify($cred, $other->assert($ch, T_RP, T_ORIGIN), $ch), WebAuthnException::class, 'Signature');
		/* Signature valid, but over other data: authenticator data changed after signing. */
		$bad = $a;
		$bad['authenticator_data'][36] = chr(ord($bad['authenticator_data'][36]) + 1);
		t_throws(fn() => lib_verify($cred, $bad, $ch), WebAuthnException::class, 'Signature');
		$bad = $a;
		$bad['signature'] = '';
		t_throws(fn() => lib_verify($cred, $bad, $ch), WebAuthnException::class, 'Signature');
	}
}

function test_lib_wrong_origin_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	foreach (['https://evil.example.com', 'http://pfsense.example.com', 'https://pfsense.example.com:8443',
	    'https://pfsense.example.com.evil.net', ''] as $origin) {
		t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, $origin), $ch), WebAuthnException::class, 'is not allowed');
	}
	/* Case and a trailing slash are normalised. */
	t_true(lib_verify($cred, $auth->assert($ch, T_RP, 'HTTPS://PFSENSE.example.com/'), $ch) > 0);
}

function test_lib_cross_origin_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['cross_origin' => true]), $ch), WebAuthnException::class, 'Cross-origin');
}

function test_lib_wrong_rp_id_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['rp_id' => 'evil.com']), $ch), WebAuthnException::class, 'RP ID hash');
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN), $ch, ['rp_id' => 'example.com']), WebAuthnException::class, 'RP ID hash');
}

function test_lib_wrong_challenge_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert(random_bytes(36), T_RP, T_ORIGIN), $ch), WebAuthnException::class, 'Challenge mismatch');
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['challenge_text' => webauthn_b64url_encode($ch) . '=']), $ch),
	    WebAuthnException::class, 'Challenge mismatch');
}

function test_lib_wrong_ceremony_type_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['type' => 'webauthn.create']), $ch), WebAuthnException::class, 'ceremony type');
}

function test_lib_replayed_or_lower_counter_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	$auth->counter = 10;
	$cred['sign_count'] = 10;
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['counter' => 10]), $ch), WebAuthnException::class, 'counter');
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['counter' => 9]), $ch), WebAuthnException::class, 'counter');
	/* A stored counter with an authenticator that now reports 0 is a clone or reset. */
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['counter' => 0]), $ch), WebAuthnException::class, 'counter');
	t_eq(11, lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['counter' => 11]), $ch));
	/* Authenticators without a counter always report 0: accepted while both are 0. */
	$cred['sign_count'] = 0;
	t_eq(0, lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['counter' => 0]), $ch));
}

function test_lib_missing_user_presence_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['flags' => WEBAUTHN_FLAG_UV]), $ch), WebAuthnException::class, 'User presence');
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['flags' => 0]), $ch), WebAuthnException::class, 'User presence');
}

function test_lib_missing_user_verification_rejected_when_required(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	t_throws(fn() => lib_verify($cred, $auth->assert($ch, T_RP, T_ORIGIN, ['flags' => WEBAUTHN_FLAG_UP]), $ch, ['uv' => true]),
	    WebAuthnException::class, 'User verification');
}

function test_lib_malformed_client_data_rejected(): void {
	$auth = new TestAuthenticator();
	$cred = lib_credential($auth);
	$ch = random_bytes(36);
	$a = $auth->assert($ch, T_RP, T_ORIGIN);
	foreach (['', 'null', '"x"', '{"type":"webauthn.get"}', '{"type":"webauthn.get","challenge":5}'] as $cd) {
		t_throws(fn() => webauthn_verify_assertion($cred, $cd, $a['authenticator_data'], $a['signature'], $ch, T_RP, [T_ORIGIN], false),
		    WebAuthnException::class);
	}
}

function test_lib_auth_data_parsing(): void {
	t_throws(fn() => webauthn_parse_auth_data(str_repeat("\0", 36)), WebAuthnException::class, 'too short');
	$base = hash('sha256', T_RP, true) . chr(WEBAUTHN_FLAG_UP) . pack('N', 7);
	t_eq(7, webauthn_parse_auth_data($base)['sign_count']);
	t_throws(fn() => webauthn_parse_auth_data($base . 'x'), WebAuthnException::class, 'Trailing');
	$at = hash('sha256', T_RP, true) . chr(WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_AT) . pack('N', 0);
	t_throws(fn() => webauthn_parse_auth_data($at . str_repeat("\0", 17)), WebAuthnException::class, 'truncated');
	t_throws(fn() => webauthn_parse_auth_data($at . str_repeat("\0", 16) . pack('n', 0)), WebAuthnException::class, 'credential ID length');
	t_throws(fn() => webauthn_parse_auth_data($at . str_repeat("\0", 16) . pack('n', 1024) . str_repeat('i', 1024)), WebAuthnException::class, 'credential ID length');
	t_throws(fn() => webauthn_parse_auth_data($at . str_repeat("\0", 16) . pack('n', 4) . 'abc'), WebAuthnException::class, 'credential ID length');
	t_throws(fn() => webauthn_parse_auth_data($at . str_repeat("\0", 16) . pack('n', 2) . 'id' . "\xa1"), WebAuthnException::class, 'public key');
	$ed = hash('sha256', T_RP, true) . chr(WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_ED) . pack('N', 0);
	webauthn_parse_auth_data($ed . cbor_encode(['credProtect' => 2]));
	t_throws(fn() => webauthn_parse_auth_data($ed), WebAuthnException::class, 'extension');
}

function test_lib_registration_checks(): void {
	$auth = new TestAuthenticator();
	$ch = random_bytes(36);
	[$cd, $att] = $auth->register($ch, T_RP, T_ORIGIN);
	t_throws(fn() => webauthn_verify_registration($cd, $att, random_bytes(36), T_RP, [T_ORIGIN], false), WebAuthnException::class, 'Challenge');
	t_throws(fn() => webauthn_verify_registration($cd, $att, $ch, 'other.example.com', [T_ORIGIN], false), WebAuthnException::class, 'RP ID hash');
	t_throws(fn() => webauthn_verify_registration($cd, $att, $ch, T_RP, ['https://other.example.com'], false), WebAuthnException::class, 'not allowed');
	t_throws(fn() => webauthn_verify_registration($cd, substr($att, 0, -1), $ch, T_RP, [T_ORIGIN], false), WebAuthnException::class, 'attestationObject');
	t_throws(fn() => webauthn_verify_registration($cd, cbor_encode(['fmt' => 'none']), $ch, T_RP, [T_ORIGIN], false), WebAuthnException::class, 'no authData');
	[$cd2, $att2] = $auth->register($ch, T_RP, T_ORIGIN, 0);
	t_throws(fn() => webauthn_verify_registration($cd2, $att2, $ch, T_RP, [T_ORIGIN], false), WebAuthnException::class, 'User presence');
	[$cd2, $att2] = $auth->register($ch, T_RP, T_ORIGIN, WEBAUTHN_FLAG_UP);
	t_throws(fn() => webauthn_verify_registration($cd2, $att2, $ch, T_RP, [T_ORIGIN], true), WebAuthnException::class, 'User verification');
	$get = json_encode(['type' => 'webauthn.get', 'challenge' => webauthn_b64url_encode($ch), 'origin' => T_ORIGIN]);
	t_throws(fn() => webauthn_verify_registration($get, $att, $ch, T_RP, [T_ORIGIN], false), WebAuthnException::class, 'ceremony type');
}

function test_lib_bad_cose_keys_rejected(): void {
	$cases = [
		'unsupported alg' => [1 => 2, 3 => -35, -1 => 1, -2 => bytes(str_repeat('a', 32)), -3 => bytes(str_repeat('a', 32))],
		'alg as text key' => [1 => 2, WEBAUTHN_CBOR_TEXT_KEY_PREFIX . '3' => -7],
		'ES256 wrong curve' => [1 => 2, 3 => -7, -1 => 2, -2 => bytes(str_repeat('a', 32)), -3 => bytes(str_repeat('a', 32))],
		'ES256 short x' => [1 => 2, 3 => -7, -1 => 1, -2 => bytes(str_repeat('a', 31)), -3 => bytes(str_repeat('a', 32))],
		'ES256 not on curve' => [1 => 2, 3 => -7, -1 => 1, -2 => bytes(str_repeat("\x01", 32)), -3 => bytes(str_repeat("\x02", 32))],
		'ES256 x as text' => [1 => 2, 3 => -7, -1 => 1, -2 => str_repeat('a', 32), -3 => bytes(str_repeat('a', 32))],
		'EdDSA wrong kty' => [1 => 2, 3 => -8, -1 => 6, -2 => bytes(str_repeat('a', 32))],
		'RS256 short key' => [1 => 3, 3 => -257, -1 => bytes(str_repeat("\xff", 128)), -2 => bytes("\x01\x00\x01")],
		'RS256 wrong kty' => [1 => 2, 3 => -257, -1 => bytes(str_repeat("\xff", 256)), -2 => bytes("\x01\x00\x01")],
	];
	foreach ($cases as $what => $cose) {
		try {
			webauthn_cose_to_pem($cose);
		} catch (WebAuthnException $e) {
			continue;
		}
		throw new TestFailure("accepted COSE key: {$what}");
	}
	t_true(true);
}

function test_lib_b64url(): void {
	foreach (['', 'a', 'ab', 'abc', "\xff\xfe\xfd", random_bytes(33)] as $s) {
		t_eq($s, webauthn_b64url_decode(webauthn_b64url_encode($s)));
	}
	t_throws(fn() => webauthn_b64url_decode('ab+/'), WebAuthnException::class);
	t_throws(fn() => webauthn_b64url_decode('abc='), WebAuthnException::class);
	t_throws(fn() => webauthn_b64url_decode('a'), WebAuthnException::class);
}

function test_lib_origin_matches_rp(): void {
	t_true(webauthn_origin_matches_rp('https://pfsense.example.com', 'example.com'));
	t_true(webauthn_origin_matches_rp('https://pfsense.example.com', 'pfsense.example.com'));
	t_true(webauthn_origin_matches_rp('http://localhost', 'localhost'));
	t_false(webauthn_origin_matches_rp('http://pfsense.example.com', 'example.com'));
	t_false(webauthn_origin_matches_rp('https://badexample.com', 'example.com'));
	t_false(webauthn_origin_matches_rp('https://pfsense.example.com/path', 'example.com'));
	t_false(webauthn_origin_matches_rp('https://user@pfsense.example.com', 'example.com'));
	t_false(webauthn_origin_matches_rp('https://192.168.1.1', '192.168.1.1'));
	t_false(webauthn_origin_matches_rp('https://x.example.com', ''));
}
