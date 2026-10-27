<?php
/* Stand-in for pfSense's config.inc, for running hook.php in tests. */
require_once(dirname(__DIR__) . '/lib/stubs.php');
$f = getenv('WEBAUTHN_TEST_CONFIG');
$GLOBALS['config'] = ($f !== false && is_file($f)) ? json_decode(file_get_contents($f), true) : [];
