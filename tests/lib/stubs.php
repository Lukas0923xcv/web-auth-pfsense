<?php
/*
 * Minimal stand-ins for the pfSense functions the package uses.
 *
 * $GLOBALS['config'] is the configuration in memory, $GLOBALS['__disk']
 * the copy "in config.xml": write_config() copies memory to disk,
 * config_read_file() and parse_xml_config() read the disk copy, as on
 * pfSense. $GLOBALS['__t'] records calls and switches failures on.
 */

$GLOBALS['config'] = $GLOBALS['config'] ?? [];
$GLOBALS['__disk'] = $GLOBALS['__disk'] ?? [];
$GLOBALS['__t'] = $GLOBALS['__t'] ?? [];

function config_get_path(string $path, $default = null) {
	$a = $GLOBALS['config'];
	foreach (explode('/', $path) as $k) {
		if (!is_array($a) || !array_key_exists($k, $a)) {
			return $default;
		}
		$a = $a[$k];
	}
	return $a;
}

function config_set_path(string $path, $value) {
	$a = &$GLOBALS['config'];
	foreach (explode('/', $path) as $k) {
		if (!isset($a[$k]) || !is_array($a[$k])) {
			$a[$k] = [];
		}
		$a = &$a[$k];
	}
	$a = $value;
	return $value;
}

function config_del_path(string $path) {
	$keys = explode('/', $path);
	$last = array_pop($keys);
	$a = &$GLOBALS['config'];
	foreach ($keys as $k) {
		if (!isset($a[$k]) || !is_array($a[$k])) {
			return null;
		}
		$a = &$a[$k];
	}
	unset($a[$last]);
	return null;
}

function write_config($desc = '') {
	if (!empty($GLOBALS['__t']['write_fail'])) {
		return false;
	}
	$GLOBALS['__t']['writes'][] = $desc;
	$GLOBALS['__disk'] = $GLOBALS['config'];
	return $GLOBALS['config'];
}

function config_read_file($parse = false, $restore = false) {
	if (!empty($GLOBALS['__t']['read_fail'])) {
		return false;
	}
	$GLOBALS['config'] = $GLOBALS['__disk'];
	return true;
}

function parse_xml_config($file, $roots) {
	return $GLOBALS['__disk'];
}

function g_get($key) {
	return ['conf_path' => '/conf', 'xml_rootobj' => 'pfsense', 'product_label' => 'pfSense'][$key] ?? null;
}

function file_notice($id, $msg, $category = '', $url = '', $priority = 1, $local_only = false) {
	$GLOBALS['__t']['notices'][] = $msg;
}

function phpsession_begin() {
	$GLOBALS['__t']['session_open'] = true;
}

function phpsession_end($write = false) {
	$GLOBALS['__t']['session_open'] = false;
}

function phpsession_destroy() {
	$GLOBALS['__t']['destroyed'] = true;
	$_SESSION = [];
}

function isAjax() {
	return !empty($GLOBALS['__t']['ajax']);
}

function get_user_settings($user) {
	return [];
}

function install_cron_job($cmd, $present, $minute = '0') {
	$GLOBALS['__t']['cron'][] = [$cmd, $present, $minute];
}

if (!function_exists('gettext')) {
	function gettext($s) {
		return $s;
	}
}
