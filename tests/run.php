<?php
/*
 * Test runner: php tests/run.php [filter]
 * Runs every test_* function in tests/*_test.php with a fresh
 * environment. Exit status 0 only if all pass.
 */

require_once(__DIR__ . '/lib/bootstrap.php');

set_error_handler(function ($no, $str, $file, $line) {
	if (!(error_reporting() & $no)) {
		return false;
	}
	throw new ErrorException($str, 0, $no, $file, $line);
});

foreach (glob(__DIR__ . '/*_test.php') as $f) {
	require_once($f);
}
$filter = $argv[1] ?? '';
$tests = array_filter(get_defined_functions()['user'], function ($fn) use ($filter) {
	return str_starts_with($fn, 'test_') && ($filter === '' || str_contains($fn, $filter));
});
sort($tests);

$failed = [];
foreach ($tests as $fn) {
	t_reset();
	try {
		$fn();
		echo "ok   {$fn}\n";
	} catch (Throwable $e) {
		$failed[] = $fn;
		echo "FAIL {$fn}: " . get_class($e) . ': ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ")\n";
	}
}
foreach (glob(TEST_DIR . '/{,.}*', GLOB_BRACE) ?: [] as $f) {
	if (is_file($f)) {
		@unlink($f);
	}
}
array_map('unlink', glob(WEBAUTHN_RUN_DIR . '/*') ?: []);
@rmdir(WEBAUTHN_RUN_DIR);
@rmdir(TEST_DIR);
printf("\n%d tests, %d passed, %d failed\n", count($tests), count($tests) - count($failed), count($failed));
exit(empty($failed) ? 0 : 1);
