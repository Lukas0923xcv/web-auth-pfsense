<?php
/*
 * webauthn_lib.inc
 *
 * Self-contained WebAuthn Level 2 relying-party verification
 * (registration and assertion). It has no pfSense dependencies so it
 * can be unit tested off-box.
 *
 * Supported algorithms: ES256 (-7), RS256 (-257), and EdDSA/Ed25519 (-8)
 * when ext/sodium is available. Attestation statements are not
 * verified: credentials are created with attestation "none", so only
 * the authenticator data is trusted, as the spec allows.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/cbor.inc');

class WebAuthnException extends Exception {}

define('WEBAUTHN_ALG_ES256', -7);
define('WEBAUTHN_ALG_EDDSA', -8);
define('WEBAUTHN_ALG_RS256', -257);

define('WEBAUTHN_FLAG_UP', 0x01);
define('WEBAUTHN_FLAG_UV', 0x04);
define('WEBAUTHN_FLAG_AT', 0x40);
define('WEBAUTHN_FLAG_ED', 0x80);

function webauthn_b64url_encode(string $data): string {
	return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function webauthn_b64url_decode(string $data): string {
	if (!preg_match('/^[A-Za-z0-9_-]*$/', $data)) {
		throw new WebAuthnException('Invalid base64url data');
	}
	$out = base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4), true);
	if ($out === false) {
		throw new WebAuthnException('Invalid base64url data');
	}
	return $out;
}

/* Algorithms this server can verify, in order of preference. */
function webauthn_supported_algs(): array {
	$algs = [WEBAUTHN_ALG_ES256];
	if (function_exists('sodium_crypto_sign_verify_detached')) {
		$algs[] = WEBAUTHN_ALG_EDDSA;
	}
	$algs[] = WEBAUTHN_ALG_RS256;
	return $algs;
}

/*
 * Is $origin a valid origin for $rp_id? The host must equal the RP ID
 * or be a subdomain of it, and the scheme must be https (browsers only
 * expose WebAuthn on secure contexts; http is allowed for localhost).
 */
function webauthn_origin_matches_rp(string $origin, string $rp_id): bool {
	$p = parse_url($origin);
	if ($p === false || empty($p['scheme']) || empty($p['host']) ||
	    isset($p['path']) || isset($p['query']) || isset($p['fragment']) || isset($p['user'])) {
		return false;
	}
	$host = strtolower($p['host']);
	$rp_id = strtolower($rp_id);
	if ($p['scheme'] != 'https' && !($p['scheme'] == 'http' && $host == 'localhost')) {
		return false;
	}
	if (filter_var($rp_id, FILTER_VALIDATE_IP) !== false || $rp_id === '') {
		return false;
	}
	return ($host === $rp_id) || str_ends_with($host, '.' . $rp_id);
}

/* Normalise an origin string to scheme://host[:port] in lower case. */
function webauthn_normalize_origin(string $origin): string {
	return strtolower(rtrim(trim($origin), '/'));
}

/*
 * Parse authenticator data (WebAuthn §6.1).
 * Returns rp_id_hash, flags, sign_count and, if the AT flag is set,
 * aaguid, credential_id and credential_public_key (decoded COSE map).
 */
function webauthn_parse_auth_data(string $raw): array {
	if (strlen($raw) < 37) {
		throw new WebAuthnException('Authenticator data too short');
	}
	$out = [
		'rp_id_hash' => substr($raw, 0, 32),
		'flags' => ord($raw[32]),
		'sign_count' => unpack('N', substr($raw, 33, 4))[1],
	];
	$offset = 37;
	if ($out['flags'] & WEBAUTHN_FLAG_AT) {
		if (strlen($raw) < $offset + 18) {
			throw new WebAuthnException('Attested credential data truncated');
		}
		$out['aaguid'] = substr($raw, $offset, 16);
		$offset += 16;
		$id_len = unpack('n', substr($raw, $offset, 2))[1];
		$offset += 2;
		if ($id_len < 1 || $id_len > 1023 || strlen($raw) < $offset + $id_len) {
			throw new WebAuthnException('Invalid credential ID length');
		}
		$out['credential_id'] = substr($raw, $offset, $id_len);
		$offset += $id_len;
		try {
			$out['credential_public_key'] = webauthn_cbor_decode_item($raw, $offset);
		} catch (WebAuthnCborException $e) {
			throw new WebAuthnException('Invalid credential public key: ' . $e->getMessage());
		}
	}
	if ($out['flags'] & WEBAUTHN_FLAG_ED) {
		try {
			webauthn_cbor_decode_item($raw, $offset);
		} catch (WebAuthnCborException $e) {
			throw new WebAuthnException('Invalid extension data: ' . $e->getMessage());
		}
	}
	if ($offset != strlen($raw)) {
		throw new WebAuthnException('Trailing bytes in authenticator data');
	}
	return $out;
}

/* DER helpers for building SubjectPublicKeyInfo structures. */
function webauthn_der_len(int $len): string {
	if ($len < 0x80) {
		return chr($len);
	}
	$s = ltrim(pack('N', $len), "\0");
	return chr(0x80 | strlen($s)) . $s;
}

function webauthn_der(int $tag, string $body): string {
	return chr($tag) . webauthn_der_len(strlen($body)) . $body;
}

function webauthn_der_uint(string $bytes): string {
	$bytes = ltrim($bytes, "\0");
	if ($bytes === '' || (ord($bytes[0]) & 0x80)) {
		$bytes = "\0" . $bytes;
	}
	return webauthn_der(0x02, $bytes);
}

function webauthn_pem(string $der): string {
	return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function webauthn_cose_bytes(array $cose, int $label, ?int $want_len = null): string {
	if (!isset($cose[$label]) || !($cose[$label] instanceof WebAuthnCborBytes)) {
		throw new WebAuthnException("COSE key parameter {$label} missing");
	}
	$b = $cose[$label]->bytes;
	if ($want_len !== null && strlen($b) != $want_len) {
		throw new WebAuthnException("COSE key parameter {$label} has wrong length");
	}
	return $b;
}

/*
 * Convert a COSE_Key map to ['alg' => int, 'pem' => PEM SPKI].
 */
function webauthn_cose_to_pem(array $cose): array {
	$kty = $cose[1] ?? null;
	$alg = $cose[3] ?? null;
	if (!in_array($alg, webauthn_supported_algs(), true)) {
		throw new WebAuthnException('Unsupported credential algorithm ' . var_export($alg, true));
	}
	switch ($alg) {
	case WEBAUTHN_ALG_ES256:
		/* kty EC2, crv P-256 */
		if ($kty !== 2 || ($cose[-1] ?? null) !== 1) {
			throw new WebAuthnException('ES256 key must be EC2 on P-256');
		}
		$x = webauthn_cose_bytes($cose, -2, 32);
		$y = webauthn_cose_bytes($cose, -3, 32);
		$der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
		break;
	case WEBAUTHN_ALG_EDDSA:
		/* kty OKP, crv Ed25519 */
		if ($kty !== 1 || ($cose[-1] ?? null) !== 6) {
			throw new WebAuthnException('EdDSA key must be OKP on Ed25519');
		}
		$x = webauthn_cose_bytes($cose, -2, 32);
		$der = hex2bin('302a300506032b6570032100') . $x;
		break;
	case WEBAUTHN_ALG_RS256:
		if ($kty !== 3) {
			throw new WebAuthnException('RS256 key must be RSA');
		}
		$n = webauthn_cose_bytes($cose, -1);
		$e = webauthn_cose_bytes($cose, -2);
		if (strlen(ltrim($n, "\0")) < 256) {
			throw new WebAuthnException('RSA key shorter than 2048 bits');
		}
		$rsa = webauthn_der(0x30, webauthn_der_uint($n) . webauthn_der_uint($e));
		$algid = hex2bin('300d06092a864886f70d0101010500');
		$der = webauthn_der(0x30, $algid . webauthn_der(0x03, "\0" . $rsa));
		break;
	}
	$pem = webauthn_pem($der);
	if ($alg != WEBAUTHN_ALG_EDDSA && openssl_pkey_get_public($pem) === false) {
		throw new WebAuthnException('Credential public key is not a valid key');
	}
	return ['alg' => $alg, 'pem' => $pem];
}

function webauthn_verify_signature(int $alg, string $pem, string $data, string $sig): bool {
	switch ($alg) {
	case WEBAUTHN_ALG_ES256:
	case WEBAUTHN_ALG_RS256:
		$key = openssl_pkey_get_public($pem);
		if ($key === false) {
			return false;
		}
		return openssl_verify($data, $sig, $key, OPENSSL_ALGO_SHA256) === 1;
	case WEBAUTHN_ALG_EDDSA:
		if (!function_exists('sodium_crypto_sign_verify_detached') || strlen($sig) != 64) {
			return false;
		}
		$der = base64_decode(preg_replace('/-----[^-]+-----|\s/', '', $pem));
		$raw = substr($der, -32);
		return sodium_crypto_sign_verify_detached($sig, $data, $raw);
	}
	return false;
}

/*
 * Validate collectedClientData (WebAuthn §7.1 steps 5-12 / §7.2 steps 10-15).
 */
function webauthn_check_client_data(string $client_data_json, string $type, string $challenge, array $allowed_origins): array {
	$cd = json_decode($client_data_json, true);
	if (!is_array($cd)) {
		throw new WebAuthnException('clientDataJSON is not valid JSON');
	}
	if (($cd['type'] ?? null) !== $type) {
		throw new WebAuthnException('Unexpected ceremony type');
	}
	if (!is_string($cd['challenge'] ?? null) || !hash_equals(webauthn_b64url_encode($challenge), $cd['challenge'])) {
		throw new WebAuthnException('Challenge mismatch');
	}
	$origin = is_string($cd['origin'] ?? null) ? webauthn_normalize_origin($cd['origin']) : '';
	$allowed = array_map('webauthn_normalize_origin', $allowed_origins);
	if ($origin === '' || !in_array($origin, $allowed, true)) {
		throw new WebAuthnException('Origin ' . ($cd['origin'] ?? '(none)') . ' is not allowed');
	}
	if (!empty($cd['crossOrigin'])) {
		throw new WebAuthnException('Cross-origin ceremonies are not allowed');
	}
	return $cd;
}

/* Parse authenticator data and check its RP ID hash and the UP (and, if required, UV) flags. */
function webauthn_check_auth_data(string $raw, string $rp_id, bool $require_uv): array {
	$ad = webauthn_parse_auth_data($raw);
	if (!hash_equals(hash('sha256', $rp_id, true), $ad['rp_id_hash'])) {
		throw new WebAuthnException('RP ID hash mismatch');
	}
	if (!($ad['flags'] & WEBAUTHN_FLAG_UP)) {
		throw new WebAuthnException('User presence flag not set');
	}
	if ($require_uv && !($ad['flags'] & WEBAUTHN_FLAG_UV)) {
		throw new WebAuthnException('User verification required but not performed');
	}
	return $ad;
}

/*
 * Verify a registration (navigator.credentials.create()) response.
 * Returns ['credential_id' => raw, 'alg' => int, 'pem' => string,
 *          'sign_count' => int, 'uv' => bool].
 */
function webauthn_verify_registration(string $client_data_json, string $attestation_object,
    string $challenge, string $rp_id, array $allowed_origins, bool $require_uv): array {
	webauthn_check_client_data($client_data_json, 'webauthn.create', $challenge, $allowed_origins);

	try {
		$att = webauthn_cbor_decode($attestation_object);
	} catch (WebAuthnCborException $e) {
		throw new WebAuthnException('Invalid attestationObject: ' . $e->getMessage());
	}
	if (!is_array($att) || !isset($att['authData']) || !($att['authData'] instanceof WebAuthnCborBytes)) {
		throw new WebAuthnException('attestationObject has no authData');
	}
	$ad = webauthn_check_auth_data($att['authData']->bytes, $rp_id, $require_uv);
	if (!isset($ad['credential_public_key']) || !is_array($ad['credential_public_key'])) {
		throw new WebAuthnException('No attested credential data');
	}
	$key = webauthn_cose_to_pem($ad['credential_public_key']);
	return [
		'credential_id' => $ad['credential_id'],
		'alg' => $key['alg'],
		'pem' => $key['pem'],
		'sign_count' => $ad['sign_count'],
		'uv' => (bool)($ad['flags'] & WEBAUTHN_FLAG_UV),
	];
}

/*
 * Verify an assertion (navigator.credentials.get()) response against a
 * stored credential (['alg' => int, 'pem' => string, 'sign_count' => int]).
 * Returns the new signature counter. $info, if passed, receives
 * ['flags' => int, 'uv' => bool] of the verified authenticator data.
 */
function webauthn_verify_assertion(array $credential, string $client_data_json, string $authenticator_data,
    string $signature, string $challenge, string $rp_id, array $allowed_origins, bool $require_uv, ?array &$info = null): int {
	webauthn_check_client_data($client_data_json, 'webauthn.get', $challenge, $allowed_origins);

	$ad = webauthn_check_auth_data($authenticator_data, $rp_id, $require_uv);

	$signed = $authenticator_data . hash('sha256', $client_data_json, true);
	if (!webauthn_verify_signature((int)$credential['alg'], $credential['pem'], $signed, $signature)) {
		throw new WebAuthnException('Signature verification failed');
	}

	/* Counter check (§7.2 step 21): only meaningful if either side is non-zero. */
	$stored = (int)($credential['sign_count'] ?? 0);
	if (($ad['sign_count'] != 0 || $stored != 0) && $ad['sign_count'] <= $stored) {
		throw new WebAuthnException('Signature counter did not increase; the authenticator may be cloned');
	}
	$info = ['flags' => $ad['flags'], 'uv' => (bool)($ad['flags'] & WEBAUTHN_FLAG_UV)];
	return $ad['sign_count'];
}
