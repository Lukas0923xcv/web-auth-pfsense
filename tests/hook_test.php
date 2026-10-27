<?php
/* hook.inc and the output of hook.php status. */

/* The pfSense 2.8.1 code each hook is anchored to. */
function hook_samples(): array {
	return [
		'authgui' => "<?php\nrequire_once(\"auth.inc\");\n\nif (!session_auth()) {\n\tdisplay_login_form();\n\texit;\n}\n\n\$x = 1;\n",
		'auth_check' => "<?php\n\$session_pagematch = session_read_single_var(\"page-match\");\nif (\$session_pagematch) {}\n",
		'xmlrpc' => "<?php\nrequire_once(\"config.inc\");\nrequire_once(\"xmlrpc_server.inc\");\n",
	];
}

function test_hook_apply_remove_roundtrip(): void {
	foreach (hook_samples() as $target => $src) {
		$new = webauthn_hook_apply($src, $target);
		t_true(is_string($new), "{$target} anchor found");
		t_true(webauthn_hook_current($new, $target), "{$target} current");
		t_true(webauthn_hook_present($new));
		t_false(webauthn_hook_current($src, $target));
		t_eq($new, webauthn_hook_apply($new, $target), "{$target} idempotent");
		t_eq($src, webauthn_hook_remove($new), "{$target} removed cleanly");
	}
}

function test_hook_placement(): void {
	$s = hook_samples();
	$a = webauthn_hook_apply($s['authgui'], 'authgui');
	t_true(strpos($a, 'webauthn_gate();') > strpos($a, 'display_login_form();'), 'gate runs after the password check');
	t_true(strpos($a, 'webauthn_gate();') < strpos($a, '$x = 1;'), 'and before the rest of authgui.inc');
	$c = webauthn_hook_apply($s['auth_check'], 'auth_check');
	t_true(strpos($c, 'webauthn_cached_privileges_allowed()') > strpos($c, 'session_read_single_var'));
	$x = webauthn_hook_apply($s['xmlrpc'], 'xmlrpc');
	t_true(strpos($x, 'webauthn_xmlrpc_guard();') < strpos($x, 'xmlrpc_server.inc'), 'guard runs before the XMLRPC server');
}

function test_hook_requires_files_unconditionally(): void {
	/* Missing package files must break the page (fail closed), not skip the check. */
	foreach (array_keys(hook_samples()) as $target) {
		$block = webauthn_hook_block($target);
		t_true(str_contains($block, "require_once('/usr/local/pkg/webauthn/"), $target);
		t_false(str_contains($block, 'include'), $target);
		t_false(str_contains($block, 'file_exists'), $target);
		t_false(str_contains($block, 'function_exists'), $target);
	}
}

function test_hook_outdated_block_replaced(): void {
	$src = hook_samples()['authgui'];
	$old = str_replace("\n}\n\n", "\n}\n\n" . WEBAUTHN_HOOK_BEGIN . "\nold();\n" . WEBAUTHN_HOOK_END . "\n", $src);
	t_true(webauthn_hook_present($old));
	t_false(webauthn_hook_current($old, 'authgui'));
	$new = webauthn_hook_apply($old, 'authgui');
	t_false(str_contains($new, 'old();'));
	t_eq(1, substr_count($new, WEBAUTHN_HOOK_BEGIN));
}

function test_hook_anchor_missing(): void {
	t_eq(null, webauthn_hook_apply("<?php\nsession_auth();\n", 'authgui'));
	t_eq(null, webauthn_hook_apply("<?php\n", 'auth_check'));
	t_eq(null, webauthn_hook_apply("<?php\nrequire_once('guiconfig.inc');\n", 'xmlrpc'));
}

function hook_status(array $config): array {
	$cfg = TEST_DIR . '/hook-config.json';
	file_put_contents($cfg, json_encode($config));
	$cmd = 'WEBAUTHN_TEST_CONFIG=' . escapeshellarg($cfg) . ' ' . escapeshellarg(PHP_BINARY) .
	    ' -d include_path=' . escapeshellarg(TEST_ROOT . '/stubs-inc') . ' ' . escapeshellarg(SRC . '/hook.php') . ' status 2>&1';
	exec($cmd, $out, $rc);
	return [$out, $rc];
}

/* "hook.php status": a version line and five state lines, unchanged. */
function test_hook_status_output_format(): void {
	if (file_exists('/etc/inc/authgui.inc')) {
		return;
	}
	$version = trim(file_get_contents(SRC . '/VERSION'));
	[$out, $rc] = hook_status([]);
	t_eq(["version: {$version}", 'authgui: hook MISSING', 'auth_check: hook MISSING', 'xmlrpc: hook MISSING',
	    'cron: re-apply job MISSING', 'boot: earlyshellcmd MISSING'], $out);
	t_eq(1, $rc);
	$cmd = '/usr/local/bin/php -f /usr/local/pkg/webauthn/hook.php ensure';
	[$out, $rc] = hook_status(['cron' => ['item' => [['command' => $cmd]]], 'system' => ['earlyshellcmd' => [$cmd]]]);
	t_eq(['cron: re-apply job present', 'boot: earlyshellcmd present'], array_slice($out, 4));
	[$out, $rc] = hook_status(['system' => ['earlyshellcmd' => $cmd]]);
	t_eq('boot: earlyshellcmd present', $out[5], 'a single earlyshellcmd is not a list in config.xml');
}
