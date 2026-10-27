<?php
/*
 * gate.inc: webauthn_gate() and the auth_check.inc check, each run as a
 * separate PHP process since the gate ends requests with exit.
 */

define('TUNNEL', ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9', 'REQUEST_URI' => '/index.php']);
define('LAN', ['REMOTE_ADDR' => '192.168.1.5', 'REQUEST_URI' => '/index.php']);

function gate(array $server = TUNNEL, array $t = []): array {
	$_SERVER = $server;
	return t_run_child('webauthn_gate', $t);
}

function test_gate_disabled_lets_through(): void {
	t_reset(['enable' => '']);
	t_register(new TestAuthenticator());
	t_true(gate()['returned']);
}

function test_gate_with_passkey_shows_challenge_and_blocks(): void {
	$a = t_register(new TestAuthenticator());
	$b = t_register(new TestAuthenticator());
	t_register(new TestAuthenticator(), 'bob', '2000');
	$_SESSION['page-match'] = ['*'];
	$r = gate();
	preg_match('/data-options="([^"]*)"/', $r['output'], $m);
	$opts = json_decode(html_entity_decode($m[1] ?? ''), true);
	t_eq([$a, $b], array_column($opts['allowCredentials'] ?? [], 'id'), 'only this user\'s passkeys offered');
	t_eq(T_RP, $opts['rpId']);
	t_false($r['returned'], 'request must not reach the page');
	t_true(str_contains($r['output'], 'id="webauthn-go"'), 'challenge page');
	t_false(isset($r['session']['page-match']), 'cached privileges dropped');
	t_false(isset($r['session']['webauthn']));
}

function test_gate_valid_assertion_verifies_session(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$_POST = t_post($auth->assert(webauthn_new_challenge('login', 'admin'), T_RP, T_ORIGIN));
	$r = gate();
	t_false($r['returned'], 'redirects after verifying');
	t_eq('webauthn', $r['session']['webauthn']['method']);
	t_eq($id, $r['session']['webauthn']['credential']);
	t_eq(T_SID, $r['session']['webauthn']['sid']);
	/* The next request of this session goes through. */
	$_POST = [];
	$_SESSION = $r['session'];
	t_true(gate()['returned']);
	/* Through the tunnel or from the LAN alike. */
	t_true(gate(LAN)['returned']);
}

function test_gate_wrong_assertion_refused_and_counted(): void {
	$auth = new TestAuthenticator();
	t_register($auth);
	$other = new TestAuthenticator();
	$_POST = t_post($other->assert(webauthn_new_challenge('login', 'admin'), T_RP, T_ORIGIN));
	$r = gate();
	t_false($r['returned']);
	t_eq(1, $r['session']['webauthn_failures']);
	t_false(isset($r['session']['webauthn']));
	t_true(str_contains($r['output'], 'Passkey verification failed'));
}

function test_gate_too_many_failures_end_session(): void {
	t_register(new TestAuthenticator());
	$_SESSION['webauthn_failures'] = WEBAUTHN_MAX_FAILURES - 1;
	$_POST = ['webauthn_action' => 'assert', 'client_data' => '', 'authenticator_data' => '', 'signature' => '', 'credential_id' => ''];
	$r = gate();
	t_false($r['returned']);
	t_true($r['destroyed'], 'session destroyed');
	t_eq(1, count($r['notices']), 'notice raised');
}

function test_gate_new_password_login_resets_verification(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$_SESSION['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, webauthn_settings());
	$_SESSION['webauthn_failures'] = 2;
	$_POST = ['login' => 'Sign In', 'usernamefld' => 'admin', 'passwordfld' => 'x'];
	$r = gate();
	t_false($r['returned']);
	t_false(isset($r['session']['webauthn']));
	t_eq(2, $r['session']['webauthn_failures'], 'failure count kept');
}

function test_gate_cancel_logs_out(): void {
	t_register(new TestAuthenticator());
	$_POST = ['webauthn_action' => 'cancel'];
	t_true(gate()['destroyed']);
}

function test_gate_no_passkey_enforced_fails_closed(): void {
	t_reset(['enforce' => 'yes']);
	$_SESSION['page-match'] = ['*'];
	$r = gate();
	t_false($r['returned']);
	t_true(str_contains($r['output'], 'has no registered passkey'), 'deny page');
	t_false(isset($r['session']['page-match']));
	/* Assertion attempts do not help. */
	$_POST = ['webauthn_action' => 'assert'];
	t_false(gate()['returned']);
}

function test_gate_no_passkey_enforce_off_lets_through(): void {
	$r = gate();
	t_true($r['returned']);
	t_eq(['user' => 'admin', 'method' => 'no-credential'], $r['session']['webauthn']);
}

function test_gate_trusted_network_skips(): void {
	t_reset(['enforce' => 'yes']);
	t_register(new TestAuthenticator());
	$r = gate(LAN);
	t_true($r['returned']);
	t_eq(['user' => 'admin', 'method' => 'trusted-network'], $r['session']['webauthn']);
	/* The exemption does not travel with the session to the tunnel. */
	$_SESSION = $r['session'];
	$_SESSION['page-match'] = ['*'];
	$r = gate();
	t_false($r['returned']);
	t_false(isset($r['session']['page-match']));
}

function test_gate_tunnel_never_trusted(): void {
	t_reset(['enforce' => 'yes', 'trusted_proxies' => '192.168.1.10']);
	t_register(new TestAuthenticator());
	/* cloudflared inside the trusted network. */
	t_false(gate(['REMOTE_ADDR' => '192.168.1.10', 'REQUEST_URI' => '/'])['returned']);
	t_false(gate(['REMOTE_ADDR' => '192.168.1.10', 'HTTP_CF_CONNECTING_IP' => '192.168.1.5', 'REQUEST_URI' => '/'])['returned']);
	/* Another proxy in the LAN, recognised by its headers. */
	t_false(gate(['REMOTE_ADDR' => '192.168.1.20', 'HTTP_X_FORWARDED_FOR' => '203.0.113.9', 'REQUEST_URI' => '/'])['returned']);
}

function test_gate_unknown_local_account_fails_closed(): void {
	$_SESSION = ['Username' => 'ghost', 'authsource' => 'Local Database'];
	$r = gate();
	t_false($r['returned']);
	t_true(str_contains($r['output'], 'has no registered passkey'));
	/* Even from a trusted network. */
	t_false(gate(LAN)['returned']);
}

function test_gate_other_spelling_with_passkeys_refused(): void {
	t_register(new TestAuthenticator(), 'carol', '');
	$_SESSION = ['Username' => 'Carol', 'authsource' => 'LDAP/corp'];
	$r = gate();
	t_false($r['returned']);
	t_true(str_contains($r['output'], 'another spelling'));
}

function test_gate_ajax_unverified_gets_401(): void {
	t_register(new TestAuthenticator());
	$r = gate(TUNNEL, ['ajax' => true]);
	t_false($r['returned']);
	t_eq(401, $r['code']);
	t_true(str_contains($r['output'], 'SESSION_TIMEOUT'));
}

function test_gate_removed_passkey_ends_session(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	t_register(new TestAuthenticator());
	$_SESSION['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, webauthn_settings());
	t_true(webauthn_delete_credential($id));
	$r = gate(LAN);
	t_false($r['returned']);
	t_true($r['destroyed']);
}

function test_gate_verification_from_other_session_not_accepted(): void {
	$auth = new TestAuthenticator();
	$id = t_register($auth);
	$_SESSION['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, webauthn_settings());
	$_COOKIE[session_name()] = 'another-session';
	t_false(gate()['returned']);
}

function test_gate_cached_privileges_check(): void {
	$id = t_register(new TestAuthenticator());
	$_SERVER = TUNNEL;
	t_false(t_run_child('webauthn_cached_privileges_allowed')['result'], 'unverified');
	$_SESSION['webauthn'] = webauthn_verified_state('admin', ['id' => $id], true, webauthn_settings());
	t_true(t_run_child('webauthn_cached_privileges_allowed')['result'], 'verified');
	$_POST = ['login' => 'x', 'usernamefld' => 'admin'];
	t_false(t_run_child('webauthn_cached_privileges_allowed')['result'], 'password login goes through authgui');
	$_POST = [];
	$_SERVER = LAN;
	unset($_SESSION['webauthn']);
	t_true(t_run_child('webauthn_cached_privileges_allowed')['result'], 'trusted network');
	t_reset(['enable' => '']);
	t_true(t_run_child('webauthn_cached_privileges_allowed')['result'], 'disabled');
}

function test_gate_page_escapes_output(): void {
	t_register(new TestAuthenticator(), 'carol', '');
	$_SESSION = ['Username' => 'carol<script>', 'authsource' => 'LDAP/corp'];
	$r = gate();
	t_false(str_contains($r['output'], '<script>'), 'username escaped');
}
