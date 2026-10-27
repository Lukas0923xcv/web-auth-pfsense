<?php
/* Child process for t_run_child(): one simulated GUI request. */

$in = json_decode(file_get_contents($argv[1]), true);
require_once(__DIR__ . '/bootstrap.php');
$GLOBALS['config'] = $in['config'];
$GLOBALS['__disk'] = $in['disk'];
$GLOBALS['__t'] = $in['t'];
$_SESSION = $in['session'];
$_SERVER = $in['server'];
$_POST = $in['post'];
$_COOKIE = $in['cookie'];
webauthn_unicode_available(true);

$GLOBALS['__warnings'] = [];
set_error_handler(function ($no, $str, $file, $line) {
	if (error_reporting() & $no) {
		$GLOBALS['__warnings'][] = "{$str} at {$file}:{$line}";
	}
	return true;
});
$GLOBALS['__returned'] = false;
$GLOBALS['__result'] = null;
ob_start();
register_shutdown_function(function () {
	$output = '';
	while (ob_get_level() > 0) {
		$output = ob_get_clean() . $output;
	}
	echo "\n@@RESULT@@" . json_encode([
		'returned' => $GLOBALS['__returned'],
		'result' => $GLOBALS['__result'],
		'session' => $_SESSION ?? null,
		'config' => $GLOBALS['config'],
		'output' => $output,
		'destroyed' => !empty($GLOBALS['__t']['destroyed']),
		'code' => http_response_code(),
		'notices' => $GLOBALS['__t']['notices'] ?? [],
		'warnings' => $GLOBALS['__warnings'],
	], JSON_INVALID_UTF8_SUBSTITUTE);
});
$GLOBALS['__result'] = ($in['call'])();
$GLOBALS['__returned'] = true;
