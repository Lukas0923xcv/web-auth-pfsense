<?php
/* webauthn.inc (and gate.inc's assertion check): storage, challenges, counters, policy. */

/* A fresh login challenge for $user and an assertion over it, as POST fields. */
function login_post(TestAuthenticator $auth, string $user = 'admin', array $o = [], ?string $purpose = 'login'): array {
	return t_post($auth->assert(webauthn_new_challenge($purpose, $user), T_RP, $o['origin'] ?? T_ORIGIN, $o));
}

function check(string $user = 'admin', ?array $settings = null) {
	return webauthn_gate_check_assertion($user, $settings ?? webauthn_settings());
}

function test_store_valid_assertion_accepted(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$_POST = login_post($auth);
	$r = check();
	t_true(is_array($r), 'accepted: ' . var_export($r, true));
	t_eq($id, $r['id']);
	t_eq(true, $r['uv']);
	t_eq(1, webauthn_get_sign_count($id));
}

function test_store_registration_record_format(): void {
	/* Saved passkeys must keep this exact shape across updates. */
	$auth = new TestAuthenticator();
	$id = t_register($auth, 'bob', '2000');
	$all = config_get_path('installedpackages/webauthn/item');
	t_eq(1, count($all));
	t_eq(['username', 'name', 'id', 'alg', 'publickey', 'rp_id', 'created', 'uid'], array_keys($all[0]));
	t_eq('bob', $all[0]['username']);
	t_eq($id, $all[0]['id']);
	t_eq('-7', $all[0]['alg']);
	t_eq(T_RP, $all[0]['rp_id']);
	t_eq('2000', $all[0]['uid']);
	t_true(str_starts_with(base64_decode($all[0]['publickey']), '-----BEGIN PUBLIC KEY-----'));
	t_eq(t_settings(), config_get_path('installedpackages/webauthn/config/0'));
	t_eq($GLOBALS['config'], $GLOBALS['__disk'], 'written to config.xml');
}

function test_store_existing_records_still_accepted(): void {
	/* A passkey record written by the current release (fixed fixture) keeps working. */
	$auth = new TestAuthenticator();
	$pem = webauthn_cose_to_pem($auth->cose)['pem'];
	$id = webauthn_b64url_encode($auth->id);
	config_set_path('installedpackages/webauthn/item', [['username' => 'admin', 'name' => 'old key', 'id' => $id,
	    'alg' => '-7', 'publickey' => base64_encode($pem), 'rp_id' => T_RP, 'created' => '1700000000', 'uid' => '0']]);
	file_put_contents(WEBAUTHN_COUNTER_FILE, json_encode([$id => 4]));
	$auth->counter = 4;
	$_POST = login_post($auth);
	t_true(is_array(check()));
	t_eq(5, webauthn_get_sign_count($id));
	/* A single record written by hand (not a list) is understood too. */
	config_set_path('installedpackages/webauthn/item', ['username' => 'admin', 'name' => 'x', 'id' => $id,
	    'alg' => '-7', 'publickey' => base64_encode($pem), 'rp_id' => T_RP, 'created' => '1700000000']);
	t_eq(1, count(webauthn_get_credentials('admin')));
}

function test_store_wrong_signature_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$_POST = login_post($auth);
	$sig = webauthn_b64url_decode($_POST['signature']);
	$sig[8] = chr(ord($sig[8]) ^ 0x40);
	$_POST['signature'] = webauthn_b64url_encode($sig);
	t_eq('Signature verification failed', check());
}

function test_store_wrong_origin_and_rp_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$_POST = login_post($auth, 'admin', ['origin' => 'https://evil.example.com']);
	t_true(str_contains((string)check(), 'is not allowed'));
	$_POST = login_post($auth, 'admin', ['rp_id' => 'evil.com']);
	t_eq('RP ID hash mismatch', check());
	/* RP ID changed in the settings since registration. */
	$_POST = login_post($auth);
	t_true(str_contains((string)check('admin', t_settings(['rp_id' => 'example.com', 'origins' => T_ORIGIN])), 'registered for RP ID'));
}

function test_store_challenge_bound_to_user_purpose_session_and_time(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	t_register(new TestAuthenticator(), 'bob', '2000');
	$invalid = 'challenge invalid, expired or already used';
	/* Issued for another user. */
	$_POST = login_post($auth, 'bob');
	t_eq($invalid, check('admin'));
	/* Issued for registration. */
	$_POST = login_post($auth, 'admin', [], 'register');
	t_eq($invalid, check());
	/* Issued in another session. */
	$_COOKIE[session_name()] = 'other-session';
	$_POST = login_post($auth);
	$_COOKIE[session_name()] = T_SID;
	t_eq($invalid, check());
	/* Made up by the client. */
	$_POST = t_post($auth->assert(random_bytes(36), T_RP, T_ORIGIN));
	t_eq($invalid, check());
	/* Expired: valid MAC, expiry in the past. */
	$payload = random_bytes(16) . pack('N', time() - 1);
	$_POST = t_post($auth->assert($payload . webauthn_challenge_mac('login', 'admin', $payload), T_RP, T_ORIGIN));
	t_eq($invalid, check());
	/* Expiring further ahead than a fresh one could. */
	$payload = random_bytes(16) . pack('N', time() + WEBAUTHN_CHALLENGE_TTL + 60);
	$_POST = t_post($auth->assert($payload . webauthn_challenge_mac('login', 'admin', $payload), T_RP, T_ORIGIN));
	t_eq($invalid, check());
	/* Truncated MAC. */
	$ch = webauthn_new_challenge('login', 'admin');
	$_POST = t_post($auth->assert(substr($ch, 0, 35), T_RP, T_ORIGIN));
	t_eq($invalid, check());
	/* The other key stays new: none of these consumed anything valid. */
	$_POST = login_post($auth);
	t_true(is_array(check()));
}

function test_store_replayed_response_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$_POST = login_post($auth);
	t_true(is_array(check()));
	t_eq('challenge invalid, expired or already used', check(), 'same response again');
}

function test_store_failed_check_does_not_use_up_challenge(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$ch = webauthn_new_challenge('login', 'admin');
	$_POST = t_post($auth->assert($ch, T_RP, T_ORIGIN, ['flags' => 0]));
	t_eq('User presence flag not set', check());
	$_POST = t_post($auth->assert($ch, T_RP, T_ORIGIN));
	t_true(is_array(check()), 'same challenge, proper response');
}

function test_store_lower_or_equal_counter_rejected(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$auth->counter = 5;
	$_POST = login_post($auth, 'admin', ['counter' => 5]);
	t_true(is_array(check()));
	/* A clone replaying the same counter on a fresh challenge. */
	$_POST = login_post($auth, 'admin', ['counter' => 5]);
	t_true(str_contains((string)check(), 'counter'));
	$_POST = login_post($auth, 'admin', ['counter' => 3]);
	t_true(str_contains((string)check(), 'counter'));
	t_eq(5, webauthn_get_sign_count($id));
}

function test_store_counter_compare_is_atomic_on_disk(): void {
	/* The stored counter moved on after the record was read: advance refuses. */
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	t_true(webauthn_advance_sign_count($id, 3));
	t_false(webauthn_advance_sign_count($id, 3));
	t_false(webauthn_advance_sign_count($id, 2));
	t_true(webauthn_advance_sign_count($id, 4));
	t_eq(4, webauthn_get_sign_count($id));
}

function test_store_unknown_credential_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$other = new TestAuthenticator();
	$_POST = login_post($other);
	t_eq('unknown credential', check());
	/* Bob's passkey does not work for admin. */
	$bob = new TestAuthenticator();
	t_register($bob, 'bob', '2000');
	$_POST = login_post($bob, 'admin');
	t_eq('unknown credential', check());
	/* Right key, credential ID of another passkey. */
	$_POST = login_post($auth);
	$_POST['credential_id'] = webauthn_b64url_encode($bob->id);
	t_eq('unknown credential', check());
}

function test_store_garbage_post_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	foreach ([[], ['client_data' => '!!'], ['client_data' => 'e30', 'authenticator_data' => '', 'signature' => '', 'credential_id' => '']] as $p) {
		$_POST = $p;
		t_true(is_string(check()));
	}
	/* An array where a string belongs is refused too (PHP warns on the cast; see the step 3 list). */
	$_POST = ['client_data' => ['x'], 'authenticator_data' => ['x'], 'signature' => ['x'], 'credential_id' => ['x']];
	t_true(is_string(@check()));
}

function test_store_case_sensitive_usernames(): void {
	$auth = new TestAuthenticator();
	t_register($auth, 'admin');
	t_eq([], webauthn_get_credentials('Admin'));
	t_eq(1, count(webauthn_get_credentials(' admin ')));
}

function test_store_revoked_credential_rejected_even_if_restored(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$saved = config_get_path('installedpackages/webauthn/item');
	t_true(webauthn_delete_credential($id));
	t_eq([], webauthn_get_credentials('admin'));
	/* A config restore brings the record back. */
	config_set_path('installedpackages/webauthn/item', $saved);
	t_eq([], webauthn_get_credentials('admin'));
	$_POST = login_post($auth);
	t_eq('unknown credential', check());
}

function test_store_damaged_files_fail_closed(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	file_put_contents(WEBAUTHN_REVOKED_FILE, 'garbage');
	$_POST = login_post($auth);
	t_eq('unknown credential', check(), 'damaged revocation list');
	t_eq(1, count(webauthn_get_credentials('admin')), 'passkey still counts as present (no skipping)');
	unlink(WEBAUTHN_REVOKED_FILE);
	file_put_contents(WEBAUTHN_COUNTER_FILE, '{broken');
	$_POST = login_post($auth);
	t_true(is_string(check()), 'damaged counter file');
	unlink(WEBAUTHN_COUNTER_FILE);
	file_put_contents(WEBAUTHN_USED_FILE, '[broken');
	$_POST = login_post($auth);
	t_eq('challenge invalid, expired or already used', check(), 'recently damaged used-challenge list');
	touch(WEBAUTHN_USED_FILE, time() - WEBAUTHN_CHALLENGE_TTL - 10);
	$_POST = login_post($auth);
	t_true(is_array(check()), 'damaged list older than any challenge');
}

function test_store_used_challenge_limits(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$who = substr(hash('sha256', 'admin'), 0, 16);
	$used = [];
	for ($i = 0; $i < WEBAUTHN_MAX_LIVE_NONCES_PER_USER; $i++) {
		$used[bin2hex(random_bytes(16))] = ['e' => time() + 100, 'u' => $who];
	}
	file_put_contents(WEBAUTHN_USED_FILE, json_encode($used));
	$_POST = login_post($auth);
	t_eq('challenge invalid, expired or already used', check(), 'per-user limit');
	/* Expired entries do not count. */
	foreach ($used as $k => $v) {
		$used[$k]['e'] = time() - 1;
	}
	file_put_contents(WEBAUTHN_USED_FILE, json_encode($used));
	t_true(is_array(check()));
}

function test_store_orphaned_passkeys_do_not_count(): void {
	$auth = new TestAuthenticator();
	t_register($auth, 'bob', '2000');
	/* bob deleted, a new bob created with another uid. */
	config_set_path('system/user/1', ['name' => 'bob', 'uid' => '2001']);
	t_eq([], webauthn_get_credentials('bob'));
	$_POST = login_post($auth, 'bob');
	t_eq('unknown credential', check('bob'));
}

function test_store_passkey_limit_per_user(): void {
	for ($i = 0; $i < WEBAUTHN_MAX_CREDENTIALS_PER_USER; $i++) {
		t_register(new TestAuthenticator());
	}
	$auth = new TestAuthenticator();
	[$cd, $att] = $auth->register(webauthn_new_challenge('register', 'admin'), T_RP, T_ORIGIN);
	$reg = webauthn_verify_registration($cd, $att, webauthn_take_challenge('register', 'admin', $cd), T_RP, [T_ORIGIN], false);
	t_true(str_contains((string)webauthn_add_credential('admin', 'k', $reg, T_RP, '0'), 'at most'));
}

function test_store_duplicate_registration_rejected(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	[$cd, $att] = $auth->register(webauthn_new_challenge('register', 'admin'), T_RP, T_ORIGIN);
	$reg = webauthn_verify_registration($cd, $att, webauthn_take_challenge('register', 'admin', $cd), T_RP, [T_ORIGIN], false);
	t_eq('This passkey is already registered.', webauthn_add_credential('admin', 'k', $reg, T_RP, '0'));
}

function test_store_reregistering_revoked_id_replaces_old_record(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$saved = config_get_path('installedpackages/webauthn/item');
	t_true(webauthn_delete_credential($id));
	config_set_path('installedpackages/webauthn/item', $saved);
	$GLOBALS['__disk'] = $GLOBALS['config'];
	t_register($auth);
	t_eq(1, count(config_get_path('installedpackages/webauthn/item')));
	t_eq([], webauthn_revoked_ids());
}

function test_store_failed_save_keeps_revocation(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$GLOBALS['__t']['write_fail'] = true;
	t_false(webauthn_delete_credential($id, null, true, $err));
	t_true(is_string($err));
	/* Not saved, but revoked anyway: it is not accepted again. */
	t_true(isset(webauthn_revoked_ids()[$id]));
	t_eq([], webauthn_get_credentials('admin'));
}

function test_store_last_usable_passkey_protected(): void {
	$a = new TestAuthenticator();
	$b = new TestAuthenticator();
	$ida = t_register($a, 'bob', '2000');
	$idb = t_register($b, 'bob', '2000');
	t_false(webauthn_delete_credential($ida, 'admin', false, $err), 'not admin\'s passkey');
	t_eq('Passkey not found.', $err);
	t_true(webauthn_delete_credential($ida, 'bob', false, $err));
	t_false(webauthn_delete_credential($idb, 'bob', false, $err));
	t_true(str_contains($err, 'last usable passkey'));
	t_true(webauthn_delete_credential($idb, 'bob', true, $err));
}

function test_store_may_register_and_delete(): void {
	$settings = webauthn_settings();
	$src = webauthn_request_source($_SERVER, $settings);
	t_true(webauthn_may_register($settings, $_SESSION, $src), 'first passkey');
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	t_false(webauthn_may_register($settings, $_SESSION, $src), 'second passkey needs a verified session');
	t_false(webauthn_may_delete($settings, $_SESSION, $src, $id, false), 'last passkey, not verified');
	t_true(webauthn_may_delete($settings, $_SESSION, $src, $id, true), 'admin may');
	$_SESSION['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, $settings);
	t_true(webauthn_may_register($settings, $_SESSION, $src));
	t_true(webauthn_may_delete($settings, $_SESSION, $src, $id, false));
	$off = t_settings(['enable' => '']);
	t_false(webauthn_may_register($off, $_SESSION, $src, false), 'disabled: users may not add more');
	t_true(webauthn_may_register($off, $_SESSION, $src, true), 'disabled: admin may');
}

/* ---- Policy: request source, trusted networks, session status ---- */

function src(array $server, ?array $settings = null): array {
	return webauthn_request_source($server, $settings ?? t_settings());
}

function test_policy_request_source(): void {
	$s = src(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9']);
	t_eq(['peer' => '127.0.0.1', 'client' => '203.0.113.9', 'via_proxy' => true, 'proxy_headers' => true], $s);
	/* CF-Connecting-IP from anyone else is not believed. */
	$s = src(['REMOTE_ADDR' => '192.168.1.5', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9']);
	t_eq('192.168.1.5', $s['client']);
	t_false($s['via_proxy']);
	t_true($s['proxy_headers']);
	t_eq('127.0.0.1', src(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => 'not-an-ip'])['client']);
	foreach (['HTTP_CF_RAY', 'HTTP_CF_ACCESS_JWT_ASSERTION', 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP'] as $h) {
		t_true(src(['REMOTE_ADDR' => '192.168.1.5', $h => 'x'])['proxy_headers'], $h);
	}
	t_eq(['peer' => '', 'client' => '', 'via_proxy' => false, 'proxy_headers' => false], src([]));
}

function test_policy_trusted_network_as_documented(): void {
	$st = t_settings();
	t_true(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.1.5']), $st), 'LAN host in trusted network');
	t_false(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.2.5']), $st), 'outside');
	/* "Tunnel traffic is never exempt, even if cloudflared sits inside one." */
	$inside = t_settings(['trusted_proxies' => '192.168.1.10']);
	t_false(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.1.10'], $inside), $inside), 'cloudflared address');
	t_false(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.1.10'], $inside), $inside), 'cloudflared without headers');
	foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP', 'HTTP_CF_RAY'] as $h) {
		t_false(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.1.5', $h => '1.2.3.4']), $st), "proxied ({$h})");
	}
	t_false(webauthn_source_is_trusted_network(src([]), $st), 'no peer');
	t_false(webauthn_source_is_trusted_network(src(['REMOTE_ADDR' => '192.168.1.5']), t_settings(['trusted_networks' => ''])), 'none configured');
}

function test_policy_cidr_matching(): void {
	t_true(webauthn_ip_in_cidr('192.168.1.200', '192.168.1.0/24'));
	t_false(webauthn_ip_in_cidr('192.168.2.1', '192.168.1.0/24'));
	t_true(webauthn_ip_in_cidr('10.1.2.3', '10.0.0.0/8'));
	t_true(webauthn_ip_in_cidr('10.0.0.1', '10.0.0.1'));
	t_false(webauthn_ip_in_cidr('10.0.0.2', '10.0.0.1'));
	t_true(webauthn_ip_in_cidr('192.168.1.129', '192.168.1.128/25'));
	t_false(webauthn_ip_in_cidr('192.168.1.127', '192.168.1.128/25'));
	t_true(webauthn_ip_in_cidr('2001:db8::1', '2001:db8::/32'));
	t_false(webauthn_ip_in_cidr('2001:db9::1', '2001:db8::/32'));
	t_false(webauthn_ip_in_cidr('::ffff:192.168.1.5', '192.168.1.0/24'), 'v4-mapped v6 is not v4');
	t_false(webauthn_ip_in_cidr('192.168.1.5', '192.168.1.0/33'));
	t_false(webauthn_ip_in_cidr('192.168.1.5', '192.168.1.0/-1'));
	t_false(webauthn_ip_in_cidr('192.168.1.5', '192.168.1.0/'));
	t_false(webauthn_ip_in_cidr('garbage', '0.0.0.0/0'));
	t_true(webauthn_ip_in_cidr('8.8.8.8', '0.0.0.0/0'));
	t_true(webauthn_cidr_too_large('10.0.0.0/7'));
	t_false(webauthn_cidr_too_large('10.0.0.0/8'));
	t_true(webauthn_cidr_too_large('10.0.0.0/00'));
	t_true(webauthn_cidr_too_large('2001::/15'));
	t_false(webauthn_cidr_too_large('2001::/16'));
}

function test_policy_session_status(): void {
	$st = t_settings();
	$tunnel = src(['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9']);
	$lan = src(['REMOTE_ADDR' => '192.168.1.5']);
	$sess = ['Username' => 'admin', 'authsource' => 'Local Database'];
	t_eq('disabled', webauthn_session_status(t_settings(['enable' => '']), $sess, $tunnel));
	t_eq('skip', webauthn_session_status($st, $sess, $tunnel), 'no passkey, enforce off');
	t_eq('deny', webauthn_session_status(t_settings(['enforce' => 'yes']), $sess, $tunnel), 'no passkey, enforce on');
	t_eq('skip', webauthn_session_status(t_settings(['enforce' => 'yes']), $sess, $lan), 'trusted network');
	$id = t_register(new TestAuthenticator());
	t_eq('require', webauthn_session_status($st, $sess, $tunnel));
	t_eq('skip', webauthn_session_status($st, $sess, $lan));
	$sess['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, $st);
	t_eq('verified', webauthn_session_status($st, $sess, $tunnel));
	/* Bound to the PHP session. */
	$_COOKIE[session_name()] = 'stolen-elsewhere';
	t_eq('require', webauthn_session_status($st, $sess, $tunnel));
	$_COOKIE[session_name()] = T_SID;
	/* Expires after 12 hours, and a time in the future is not trusted. */
	$old = $sess;
	$old['webauthn']['time'] = time() - WEBAUTHN_VERIFIED_MAX_AGE - 1;
	t_eq('require', webauthn_session_status($st, $old, $tunnel));
	$old['webauthn']['time'] = time() + 60;
	t_eq('require', webauthn_session_status($st, $old, $tunnel));
	/* Stronger settings now: UV required, verified without. */
	$weak = $sess;
	$weak['webauthn']['uv'] = false;
	t_eq('require', webauthn_session_status(t_settings(['user_verification' => 'required']), $weak, $tunnel));
	t_eq('verified', webauthn_session_status($st, $weak, $tunnel));
	/* Other RP ID now. */
	t_eq('require', webauthn_session_status(t_settings(['rp_id' => 'example.com']), $sess, $tunnel));
	/* State of another user. */
	$other = $sess;
	$other['Username'] = 'bob';
	t_eq('skip', webauthn_session_status($st, $other, $tunnel));
	/* Passkey removed since. */
	t_true(webauthn_delete_credential($id));
	t_eq('revoked', webauthn_session_status($st, $sess, $tunnel));
	t_eq('revoked', webauthn_session_status($st, $sess, $lan), 'even on a trusted network');
}

function test_policy_local_name_resolution(): void {
	$st = t_settings();
	$tunnel = src(['REMOTE_ADDR' => '127.0.0.1']);
	/* A local name that is no account fails closed. */
	t_eq('', webauthn_session_identity(['Username' => 'nobody', 'authsource' => 'Local Database']));
	t_eq('require', webauthn_session_status($st, ['Username' => 'nobody', 'authsource' => 'Local Database'], $tunnel));
	/* Surrounding spaces are trimmed before the lookup; other spellings are other accounts. */
	t_eq('admin', webauthn_session_identity(['Username' => ' admin ', 'authsource' => 'Local Database']));
	t_eq('', webauthn_session_identity(['Username' => 'Admin', 'authsource' => 'Local Database']));
	t_eq('require', webauthn_session_status($st, ['Username' => 'Admin', 'authsource' => 'Local Database'], $tunnel));
	t_register(new TestAuthenticator());
	t_eq('require', webauthn_session_status($st, ['Username' => ' admin ', 'authsource' => 'Local Database'], $tunnel));
	/* "Local Database Fallback" is local too. */
	t_true(webauthn_session_is_local(['authsource' => 'Local Database Fallback']));
	t_false(webauthn_session_is_local(['authsource' => 'LDAP/corp']));
}

function test_policy_remote_spellings_cannot_skip(): void {
	$st = t_settings();
	$tunnel = src(['REMOTE_ADDR' => '127.0.0.1']);
	t_register(new TestAuthenticator(), 'carol', '');
	foreach (['Carol', 'CAROL', 'carol@corp.example', 'CORP\\carol', 'carol%realm', 'corp/carol', "carol\u{00AD}", 'ｃａｒｏｌ'] as $name) {
		t_eq('require', webauthn_session_status($st, ['Username' => $name, 'authsource' => 'LDAP/corp'], $tunnel), $name);
		t_eq('require', webauthn_session_status($st, ['Username' => $name, 'authsource' => 'RADIUS/r'], $tunnel), $name);
	}
	t_eq('skip', webauthn_session_status($st, ['Username' => 'dave', 'authsource' => 'LDAP/corp'], $tunnel));
	/* Without intl/mbstring, any passkey counts for every remote user. */
	webauthn_unicode_available(false);
	t_eq('require', webauthn_session_status($st, ['Username' => 'dave', 'authsource' => 'LDAP/corp'], $tunnel));
	webauthn_unicode_available(true);
}

function test_policy_registrable_names(): void {
	t_true(webauthn_registrable_name(['Username' => 'admin', 'authsource' => 'Local Database']));
	t_false(webauthn_registrable_name(['Username' => 'nobody', 'authsource' => 'Local Database']));
	t_true(webauthn_registrable_name(['Username' => 'carol', 'authsource' => 'LDAP/corp']));
	t_false(webauthn_registrable_name(['Username' => 'x\\carol', 'authsource' => 'LDAP/corp']));
	t_false(webauthn_registrable_name(['Username' => 'x/carol', 'authsource' => 'RADIUS/r']));
	t_false(webauthn_registrable_name(['Username' => "car\u{202E}ol", 'authsource' => 'LDAP/corp']));
	t_false(webauthn_registrable_name(['Username' => "car\xffol", 'authsource' => 'LDAP/corp']));
}

function test_policy_settings_validation(): void {
	t_eq([], webauthn_validate_settings(t_settings()));
	$bad = function (array $over) {
		return count(webauthn_validate_settings(t_settings($over))) > 0;
	};
	t_true($bad(['rp_id' => '']), 'enabled without RP ID');
	t_true($bad(['rp_id' => '192.168.1.1', 'origins' => '']));
	t_true($bad(['rp_id' => 'localhost', 'origins' => '']));
	t_true($bad(['origins' => 'http://pfsense.example.com']));
	t_true($bad(['origins' => 'https://evil.com']));
	t_true($bad(['trusted_networks' => '192.168.1.0/33']));
	t_true($bad(['trusted_networks' => '0.0.0.0/0']));
	t_true($bad(['xmlrpc_peers' => '10.0.0.0/7']));
	t_true($bad(['trusted_proxies' => 'cloudflared']));
	t_true($bad(['trusted_proxies' => '']), 'trusted networks need the cloudflared source');
	t_true($bad(['user_verification' => 'always']));
	t_eq([], webauthn_validate_settings(t_settings(['trusted_proxies' => '', 'trusted_networks' => ''])));
}

function test_policy_settings_lockout(): void {
	$tunnel = src(['REMOTE_ADDR' => '127.0.0.1']);
	t_true(is_string(webauthn_settings_lockout_error(t_settings(['enforce' => 'yes']), $tunnel, [])), 'enforce without own passkey');
	t_eq(null, webauthn_settings_lockout_error(t_settings(['enforce' => 'yes']), src(['REMOTE_ADDR' => '192.168.1.5']), []));
	$mine = [['rp_id' => T_RP]];
	t_eq(null, webauthn_settings_lockout_error(t_settings(['enforce' => 'yes']), $tunnel, $mine));
	t_true(is_string(webauthn_settings_lockout_error(t_settings(['rp_id' => 'example.com']), $tunnel, $mine)), 'RP ID change');
	t_eq(null, webauthn_settings_lockout_error(t_settings(['enable' => '']), $tunnel, []));
}

function test_policy_safe_redirect(): void {
	t_eq('/index.php?x=1', webauthn_safe_redirect('/index.php?x=1'));
	foreach (['', 'https://evil.com', '//evil.com', '/\\evil.com', "/x\r\nSet-Cookie: a", 'index.php'] as $u) {
		t_eq('/', webauthn_safe_redirect($u), $u);
	}
}

function test_policy_config_state_change_raises_notice(): void {
	/* A change outside the package (restore, stale save) raises one notice. */
	t_false(webauthn_check_config_state(), 'first sight just records');
	t_false(webauthn_check_config_state());
	config_set_path(WEBAUTHN_CONFIG_PATH . '/enable', '');
	$GLOBALS['__disk'] = $GLOBALS['config'];
	t_true(webauthn_check_config_state());
	t_eq(1, count($GLOBALS['__t']['notices'] ?? []));
	t_false(webauthn_check_config_state());
	/* The package's own saves do not. */
	webauthn_save_settings(t_settings());
	t_false(webauthn_check_config_state());
}

function test_policy_plain_and_log_text(): void {
	t_eq('a b', webauthn_plain("a\nb"));
	t_eq('a b', webauthn_plain("a\u{202E}b"));
	t_eq(str_repeat('x', 64) . '…', webauthn_plain(str_repeat('x', 100)));
	t_true(mb_check_encoding(webauthn_plain("bad\xff"), 'UTF-8'));
	t_true(webauthn_valid_passkey_name('YubiKey 5 (blue)'));
	t_false(webauthn_valid_passkey_name(''));
	t_false(webauthn_valid_passkey_name('<script>'));
	t_false(webauthn_valid_passkey_name(str_repeat('a', 65)));
}

function test_policy_failure_notice_rate_limited(): void {
	webauthn_notice('one', 'k');
	webauthn_notice('two', 'k');
	webauthn_notice('three', 'other');
	t_eq(['one', 'three'], $GLOBALS['__t']['notices']);
}
