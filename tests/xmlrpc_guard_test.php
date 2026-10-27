<?php
/* xmlrpc_guard.inc */

function xr(array $server, array $settings): bool {
	return webauthn_xmlrpc_refused(webauthn_request_source($server, $settings), $settings);
}

function test_xmlrpc_proxied_always_refused(): void {
	foreach ([t_settings(), t_settings(['enable' => '']), t_settings(['enable' => '', 'trusted_proxies' => ''])] as $st) {
		foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_CF_RAY', 'HTTP_CF_ACCESS_JWT_ASSERTION', 'HTTP_X_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_X_REAL_IP'] as $h) {
			t_true(xr(['REMOTE_ADDR' => '10.10.10.2', $h => '1.2.3.4'], $st), "{$h}, enable=" . $st['enable']);
		}
	}
	t_true(xr(['REMOTE_ADDR' => '127.0.0.1'], t_settings(['enable' => ''])), 'cloudflared while disabled');
}

function test_xmlrpc_enabled_only_peers_and_trusted_networks(): void {
	$st = t_settings();
	t_false(xr(['REMOTE_ADDR' => '10.10.10.2'], $st), 'HA peer');
	t_false(xr(['REMOTE_ADDR' => '192.168.1.5'], $st), 'trusted network');
	t_true(xr(['REMOTE_ADDR' => '10.10.10.3'], $st), 'other LAN host');
	t_true(xr(['REMOTE_ADDR' => '8.8.8.8'], $st));
	t_true(xr([], $st), 'no peer address');
	t_true(xr(['REMOTE_ADDR' => '10.10.10.2'], t_settings(['xmlrpc_peers' => '', 'trusted_networks' => ''])));
}

function test_xmlrpc_disabled_direct_allowed(): void {
	t_false(xr(['REMOTE_ADDR' => '10.10.10.3'], t_settings(['enable' => ''])));
}

function test_xmlrpc_guard_sends_403_and_stops(): void {
	$_SERVER = ['REMOTE_ADDR' => '8.8.8.8'];
	$r = t_run_child('webauthn_xmlrpc_guard');
	t_false($r['returned']);
	t_eq(403, $r['code']);
	$_SERVER = ['REMOTE_ADDR' => '10.10.10.2'];
	t_true(t_run_child('webauthn_xmlrpc_guard')['returned']);
}
