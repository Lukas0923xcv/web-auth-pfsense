<?php
/*
 * Test bootstrap: points the package's state files at a scratch
 * directory and stubs the few pfSense functions the code calls. Nothing
 * here is installed on pfSense (install.sh only copies from src/).
 */

error_reporting(E_ALL);
define('TEST_ROOT', dirname(__DIR__));
define('SRC', dirname(__DIR__, 2) . '/src/usr/local/pkg/webauthn');

$dir = getenv('WEBAUTHN_TEST_DIR');
if ($dir === false || $dir === '') {
	$dir = sys_get_temp_dir() . '/webauthn-test-' . getmypid();
	putenv('WEBAUTHN_TEST_DIR=' . $dir);
}
@mkdir($dir, 0700, true);
define('TEST_DIR', $dir);

define('WEBAUTHN_COUNTER_FILE', TEST_DIR . '/signcount.json');
define('WEBAUTHN_KEY_FILE', TEST_DIR . '/challenge.key');
define('WEBAUTHN_USED_FILE', TEST_DIR . '/used.json');
define('WEBAUTHN_REVOKED_FILE', TEST_DIR . '/revoked.json');
define('WEBAUTHN_CONFIG_LOCK', TEST_DIR . '/config');
define('WEBAUTHN_NOTICE_FILE', TEST_DIR . '/notices.json');
define('WEBAUTHN_RUN_DIR', TEST_DIR . '/run');
define('WEBAUTHN_STATE_FILE', TEST_DIR . '/state.json');
@mkdir(WEBAUTHN_RUN_DIR, 0700, true);

require_once(__DIR__ . '/stubs.php');
require_once(SRC . '/gate.inc');
require_once(SRC . '/xmlrpc_guard.inc');
require_once(SRC . '/hook.inc');
require_once(__DIR__ . '/fixtures.php');
