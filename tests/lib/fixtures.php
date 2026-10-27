<?php
/* Test helpers: assertions, a CBOR encoder, software authenticators, environment setup. */

class TestFailure extends Exception {}

function t_true($cond, string $msg = 'expected true'): void {
	if ($cond !== true) {
		throw new TestFailure($msg);
	}
}

function t_false($cond, string $msg = 'expected false'): void {
	if ($cond !== false) {
		throw new TestFailure($msg);
	}
}

function t_eq($expected, $actual, string $msg = ''): void {
	if ($expected !== $actual) {
		throw new TestFailure(($msg !== '' ? $msg . ': ' : '') . 'expected ' . var_export($expected, true) .
		    ', got ' . var_export($actual, true));
	}
}

/* $fn must throw $class; if $contains is given, the message must contain it. */
function t_throws(callable $fn, string $class, ?string $contains = null): void {
	try {
		$fn();
	} catch (Throwable $e) {
		if (!($e instanceof $class)) {
			throw new TestFailure("expected {$class}, got " . get_class($e) . ': ' . $e->getMessage());
		}
		if ($contains !== null && !str_contains($e->getMessage(), $contains)) {
			throw new TestFailure("expected message containing '{$contains}', got '" . $e->getMessage() . "'");
		}
		return;
	}
	throw new TestFailure("expected {$class}, nothing thrown");
}

/* ---- CBOR encoder (test side only) ---- */

class TestCborMap {
	public function __construct(public array $pairs) {}
}

function cbor_head(int $major, int $arg): string {
	if ($arg < 24) {
		return chr(($major << 5) | $arg);
	}
	if ($arg < 0x100) {
		return chr(($major << 5) | 24) . chr($arg);
	}
	if ($arg < 0x10000) {
		return chr(($major << 5) | 25) . pack('n', $arg);
	}
	if ($arg < 0x100000000) {
		return chr(($major << 5) | 26) . pack('N', $arg);
	}
	return chr(($major << 5) | 27) . pack('J', $arg);
}

/* Lists encode as arrays, other PHP arrays and TestCborMap as maps. */
function cbor_encode($v): string {
	if ($v instanceof WebAuthnCborBytes) {
		return cbor_head(2, strlen($v->bytes)) . $v->bytes;
	}
	if ($v instanceof TestCborMap) {
		$out = cbor_head(5, count($v->pairs));
		foreach ($v->pairs as [$k, $x]) {
			$out .= cbor_encode($k) . cbor_encode($x);
		}
		return $out;
	}
	if (is_int($v)) {
		return $v >= 0 ? cbor_head(0, $v) : cbor_head(1, -1 - $v);
	}
	if (is_string($v)) {
		return cbor_head(3, strlen($v)) . $v;
	}
	if (is_bool($v)) {
		return chr($v ? 0xf5 : 0xf4);
	}
	if ($v === null) {
		return chr(0xf6);
	}
	if (is_array($v) && array_is_list($v)) {
		return cbor_head(4, count($v)) . implode('', array_map('cbor_encode', $v));
	}
	$pairs = [];
	foreach ($v as $k => $x) {
		$pairs[] = [$k, $x];
	}
	return cbor_encode(new TestCborMap($pairs));
}

function bytes(string $s): WebAuthnCborBytes {
	return new WebAuthnCborBytes($s);
}

/* ---- Software authenticator ---- */

class TestAuthenticator {
	public string $id;
	public int $counter = 0;
	public $priv;
	public array $cose;

	public function __construct(public int $alg = WEBAUTHN_ALG_ES256, ?string $id = null) {
		$this->id = $id ?? random_bytes(16);
		if ($alg == WEBAUTHN_ALG_ES256) {
			$this->priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
			$d = openssl_pkey_get_details($this->priv)['ec'];
			$this->cose = [1 => 2, 3 => -7, -1 => 1, -2 => bytes(str_pad($d['x'], 32, "\0", STR_PAD_LEFT)),
			    -3 => bytes(str_pad($d['y'], 32, "\0", STR_PAD_LEFT))];
		} elseif ($alg == WEBAUTHN_ALG_RS256) {
			$this->priv = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
			$d = openssl_pkey_get_details($this->priv)['rsa'];
			$this->cose = [1 => 3, 3 => -257, -1 => bytes($d['n']), -2 => bytes($d['e'])];
		} else {
			$kp = sodium_crypto_sign_keypair();
			$this->priv = sodium_crypto_sign_secretkey($kp);
			$this->cose = [1 => 1, 3 => -8, -1 => 6, -2 => bytes(sodium_crypto_sign_publickey($kp))];
		}
	}

	public function sign(string $data): string {
		if ($this->alg == WEBAUTHN_ALG_EDDSA) {
			return sodium_crypto_sign_detached($data, $this->priv);
		}
		openssl_sign($data, $sig, $this->priv, OPENSSL_ALGO_SHA256);
		return $sig;
	}

	/* navigator.credentials.create(): [clientDataJSON, attestationObject]. */
	public function register(string $challenge, string $rp_id, string $origin, int $flags = WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV): array {
		$cd = json_encode(['type' => 'webauthn.create', 'challenge' => webauthn_b64url_encode($challenge),
		    'origin' => $origin, 'crossOrigin' => false]);
		$ad = hash('sha256', $rp_id, true) . chr($flags | WEBAUTHN_FLAG_AT) . pack('N', $this->counter) .
		    str_repeat("\0", 16) . pack('n', strlen($this->id)) . $this->id . cbor_encode($this->cose);
		$att = cbor_encode(new TestCborMap([['fmt', 'none'], ['attStmt', new TestCborMap([])], ['authData', bytes($ad)]]));
		return [$cd, $att];
	}

	/*
	 * navigator.credentials.get(): ['client_data', 'authenticator_data',
	 * 'signature', 'credential_id'] (raw). $o overrides: type, origin,
	 * rp_id (hashed into authData), flags, counter, cross_origin,
	 * challenge_text (the raw clientData challenge string).
	 */
	public function assert(string $challenge, string $rp_id, string $origin, array $o = []): array {
		if (!array_key_exists('counter', $o)) {
			$this->counter++;
		}
		$cd = ['type' => $o['type'] ?? 'webauthn.get',
		    'challenge' => $o['challenge_text'] ?? webauthn_b64url_encode($challenge), 'origin' => $origin];
		if (isset($o['cross_origin'])) {
			$cd['crossOrigin'] = $o['cross_origin'];
		}
		$cd = json_encode($cd);
		$ad = hash('sha256', $o['rp_id'] ?? $rp_id, true) . chr($o['flags'] ?? (WEBAUTHN_FLAG_UP | WEBAUTHN_FLAG_UV)) .
		    pack('N', $o['counter'] ?? $this->counter);
		return ['client_data' => $cd, 'authenticator_data' => $ad,
		    'signature' => $this->sign($ad . hash('sha256', $cd, true)), 'credential_id' => $this->id];
	}
}

/* ---- Environment ---- */

define('T_RP', 'pfsense.example.com');
define('T_ORIGIN', 'https://pfsense.example.com');
define('T_SID', 'sid-test-1');

function t_settings(array $over = []): array {
	return array_merge(webauthn_default_settings(), [
		'enable' => 'yes',
		'rp_id' => T_RP,
		'origins' => T_ORIGIN,
		'trusted_proxies' => '127.0.0.1',
		'trusted_networks' => '192.168.1.0/24',
		'user_verification' => 'preferred',
		'enforce' => '',
		'xmlrpc_peers' => '10.10.10.2',
	], $over);
}

/* Fresh config, state files and session for one test. */
function t_reset(array $settings_over = []): void {
	foreach (glob(TEST_DIR . '/*') as $f) {
		if (is_file($f)) {
			unlink($f);
		}
	}
	foreach (glob(WEBAUTHN_RUN_DIR . '/*') as $f) {
		unlink($f);
	}
	$GLOBALS['config'] = [
		'system' => [
			'user' => [
				['name' => 'admin', 'uid' => '0'],
				['name' => 'bob', 'uid' => '2000'],
			],
			'hostname' => 'pfsense',
			'domain' => 'example.com',
		],
	];
	config_set_path(WEBAUTHN_CONFIG_PATH, t_settings($settings_over));
	$GLOBALS['__disk'] = $GLOBALS['config'];
	$GLOBALS['__t'] = [];
	$_SESSION = ['Username' => 'admin', 'authsource' => 'Local Database'];
	$_COOKIE = [session_name() => T_SID];
	$_POST = [];
	$_SERVER = ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_CF_CONNECTING_IP' => '203.0.113.9', 'REQUEST_URI' => '/index.php'];
	webauthn_unicode_available(true);
}

/* Register $auth for $user through the package's own registration path. Returns the stored ID. */
function t_register(TestAuthenticator $auth, string $user = 'admin', string $uid = '0'): string {
	$settings = webauthn_settings();
	[$cd, $att] = $auth->register(webauthn_new_challenge('register', $user), T_RP, T_ORIGIN);
	$reg = webauthn_use_challenge('register', $user, $cd, function ($c) use ($cd, $att, $settings) {
		return webauthn_verify_registration($cd, $att, $c, webauthn_rp_id($settings),
		    webauthn_allowed_origins($settings), webauthn_require_uv($settings));
	});
	t_true(is_array($reg), 'registration verified');
	t_eq(null, webauthn_add_credential($user, 'key', $reg, T_RP, $uid), 'credential stored');
	return webauthn_b64url_encode($auth->id);
}

/* The POST fields the login page submits, base64url encoded. */
function t_post(array $a): array {
	return ['webauthn_action' => 'assert',
	    'client_data' => webauthn_b64url_encode($a['client_data']),
	    'authenticator_data' => webauthn_b64url_encode($a['authenticator_data']),
	    'signature' => webauthn_b64url_encode($a['signature']),
	    'credential_id' => webauthn_b64url_encode($a['credential_id'])];
}

/*
 * Run webauthn_gate() (or $call) in a child PHP process, since it ends
 * requests with exit. The child gets the current config, $_SESSION,
 * $_SERVER, $_POST, $_COOKIE and state directory. Returns
 * ['returned' => bool (the request was let through), 'session', 'output',
 *  'destroyed', 'code', 'notices', 'warnings'].
 */
function t_run_child(string $call = 'webauthn_gate', array $extra = []): array {
	$in = TEST_DIR . '/child-in.json';
	file_put_contents($in, json_encode(['config' => $GLOBALS['config'], 'disk' => $GLOBALS['__disk'],
	    'session' => $_SESSION, 'server' => $_SERVER, 'post' => $_POST, 'cookie' => $_COOKIE,
	    't' => $extra, 'call' => $call]));
	$cmd = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(__DIR__ . '/child.php') . ' ' . escapeshellarg($in) . ' 2>&1';
	$out = shell_exec($cmd);
	$pos = strrpos((string)$out, "\n@@RESULT@@");
	if ($pos === false) {
		throw new TestFailure("child produced no result:\n" . $out);
	}
	$r = json_decode(substr($out, $pos + 11), true);
	$unexpected = array_filter($r['warnings'], function ($w) {
		/* Expected in the CLI: no real session to regenerate, no pfSense logo file. */
		return !str_contains($w, 'session_regenerate_id') && !str_contains($w, 'logo.svg');
	});
	if (!empty($unexpected)) {
		throw new TestFailure("unexpected PHP warnings in child:\n" . implode("\n", $unexpected));
	}
	return $r;
}
