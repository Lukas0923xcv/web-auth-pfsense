<?php
/*
 * webauthn.inc
 *
 * pfSense glue for the WebAuthn second factor: settings, credential
 * storage, access-path policy (Cloudflare Tunnel / trusted networks),
 * client IP resolution, and logging.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/webauthn_lib.inc');

define('WEBAUTHN_CONFIG_PATH', 'installedpackages/webauthn/config/0');
/*
 * Lists in config.xml must use a tag from pfSense's listtags() set
 * (xmlparse.inc); any other tag holding a list is written as <0>, <1>,
 * ... which is invalid XML and makes pfSense restore a backup.
 */
define('WEBAUTHN_CRED_PATH', 'installedpackages/webauthn/item');
if (!defined('WEBAUTHN_COUNTER_FILE')) {
	define('WEBAUTHN_COUNTER_FILE', '/conf/webauthn_signcount.json');
}
if (!defined('WEBAUTHN_KEY_FILE')) {
	define('WEBAUTHN_KEY_FILE', '/conf/webauthn_challenge.key');
}
if (!defined('WEBAUTHN_USED_FILE')) {
	/* Kept on disk: losing the list (e.g. at reboot) would make used challenges valid again. */
	define('WEBAUTHN_USED_FILE', '/conf/webauthn_used_challenges.json');
}
if (!defined('WEBAUTHN_REVOKED_FILE')) {
	/* IDs of removed passkeys: never accepted again, even if a config
	 * restore or a stale write brings the record back. */
	define('WEBAUTHN_REVOKED_FILE', '/conf/webauthn_revoked.json');
}
if (!defined('WEBAUTHN_CONFIG_LOCK')) {
	/* Serialises changes to installedpackages/webauthn (".lock" is appended). */
	define('WEBAUTHN_CONFIG_LOCK', '/conf/webauthn_config');
}
if (!defined('WEBAUTHN_NOTICE_FILE')) {
	define('WEBAUTHN_NOTICE_FILE', '/conf/webauthn_notices.json');
}
if (!defined('WEBAUTHN_RUN_DIR')) {
	/* Fallback markers when /conf cannot be written (cleared at reboot). */
	define('WEBAUTHN_RUN_DIR', '/var/run');
}
if (!defined('WEBAUTHN_STATE_FILE')) {
	/* Hash of installedpackages/webauthn as last saved by this package. */
	define('WEBAUTHN_STATE_FILE', '/conf/webauthn_state.json');
}
define('WEBAUTHN_MAX_FAILURES', 5);
define('WEBAUTHN_CHALLENGE_TTL', 300);
/* A passkey verification is good for this long at most (seconds). */
define('WEBAUTHN_VERIFIED_MAX_AGE', 12 * 3600);
/* Upper bound for unexpired entries in the used-challenge list, in all and per user. */
define('WEBAUTHN_MAX_LIVE_NONCES', 10000);
define('WEBAUTHN_MAX_LIVE_NONCES_PER_USER', 50);
/* Passkeys per account. */
define('WEBAUTHN_MAX_CREDENTIALS_PER_USER', 20);
/* At most one failed-attempt notice per user in this many seconds. */
define('WEBAUTHN_NOTICE_INTERVAL', 900);

function webauthn_default_settings(): array {
	return [
		'enable' => '',
		/* RP ID: the public hostname, or a parent domain of it. */
		'rp_id' => '',
		/* Origins allowed in clientDataJSON, one per line. */
		'origins' => '',
		/* Source addresses of cloudflared (IPs or CIDRs). */
		'trusted_proxies' => '',
		/* Source networks that skip the WebAuthn step. */
		'trusted_networks' => '',
		/* discouraged | preferred | required */
		'user_verification' => 'preferred',
		/* Users without a passkey are refused unless on a trusted network. */
		'enforce' => '',
		/* Source addresses allowed to use XMLRPC (HA sync) while enabled. */
		'xmlrpc_peers' => '',
	];
}

/* The installed version of this package (the VERSION file next to this one). */
function webauthn_version(): string {
	$v = trim((string)@file_get_contents(__DIR__ . '/VERSION'));
	return preg_match('/^[0-9A-Za-z.\-]{1,32}$/', $v) ? $v : 'unknown';
}

function webauthn_settings(): array {
	$s = config_get_path(WEBAUTHN_CONFIG_PATH, []);
	return array_merge(webauthn_default_settings(), is_array($s) ? $s : []);
}

/*
 * Passkeys belong to the exact username (surrounding spaces trimmed).
 * pfSense local accounts are case-sensitive, so "Bob" and "bob" can be
 * two different people: they must never share passkeys.
 */
function webauthn_normalize_username(?string $username): string {
	return trim((string)$username);
}

/*
 * Can usernames be compared the way directories do? That needs PHP's intl
 * (Normalizer) and mbstring extensions. $set overrides the answer (tests).
 */
function webauthn_unicode_available(?bool $set = null): bool {
	static $override = null;
	if ($set !== null) {
		$override = $set;
	}
	return $override ?? (class_exists('Normalizer') && function_exists('mb_convert_case') && function_exists('mb_convert_kana'));
}

/*
 * A username the way directories compare names (RFC 4518): compatibility
 * forms (NFKC), no soft hyphens, zero-width or other ignorable characters,
 * runs of spaces collapsed, case folded, katakana as hiragana (Active
 * Directory ignores the kana type). Without intl/mbstring only ASCII is
 * folded; webauthn_session_has_credentials() then fails closed.
 */
function webauthn_username_fold(?string $username): string {
	$u = (string)$username;
	$unicode = webauthn_unicode_available();
	if ($unicode) {
		$n = Normalizer::normalize($u, Normalizer::FORM_KC);
		$u = ($n === false) ? $u : $n;
	}
	$u = preg_replace('/[\p{Cf}\p{Cc}\x{034F}\x{1806}\x{180B}-\x{180D}\x{FE00}-\x{FE0F}\x{FFFC}]/u', '', $u) ?? $u;
	$u = trim(preg_replace('/[\p{Z}\s]+/u', ' ', $u) ?? $u);
	if (!$unicode) {
		return strtolower($u);
	}
	return mb_convert_kana(mb_convert_case($u, MB_CASE_FOLD, 'UTF-8'), 'c', 'UTF-8');
}

/*
 * The account names an authentication backend may take $username to
 * mean, used only to stop other spellings of a remote (LDAP/RADIUS)
 * account from skipping the passkey step. pfSense's LDAP code keeps the
 * part before "@" and before "\"; RADIUS servers usually strip a realm
 * ("user@realm", "user%realm", "REALM\user", "realm/user"). So "admin@x", "admin\x",
 * "CORP\admin" and "ADMIN" can all sign in as "admin".
 *
 * $login: the name typed at sign-in. Only for it is the part before "\"
 * a candidate (pfSense's LDAP quirk); for a stored passkey owner it is
 * just a domain, and two users of one domain must not match each other.
 */
function webauthn_username_keys(?string $username, bool $login): array {
	$u = webauthn_username_fold($username);
	$parts = [$u];
	if (str_contains($u, '\\')) {
		[$before, $after] = explode('\\', $u, 2);
		$parts[] = $after;
		if ($login) {
			$parts[] = $before;
		}
	}
	if (str_contains($u, '/')) {
		$parts[] = substr($u, strrpos($u, '/') + 1);
	}
	$keys = [];
	foreach ($parts as $p) {
		$keys[] = trim($p);
		/* "user@realm" and "user%realm" */
		$keys[] = trim(preg_split('/[@%]/', $p, 2)[0]);
	}
	return array_values(array_unique(array_filter($keys, 'strlen')));
}

/*
 * Did this session sign in against pfSense's own user database? Local
 * names are exact and case-sensitive: "Bob" and "bob" are two accounts.
 */
function webauthn_session_is_local(array $session): bool {
	return in_array($session['authsource'] ?? null, ['Local Database', 'Local Database Fallback'], true);
}

/*
 * The local account named $name, or null. pfSense's getUserEntry() looks
 * names up through an array index; PHP turns only canonical decimal
 * strings into integer keys, so that lookup is an exact string match,
 * which this repeats without depending on auth.inc being loaded. With
 * duplicate names the last entry wins, as in pfSense's index.
 */
function webauthn_local_user(string $name): ?array {
	$found = null;
	$users = config_get_path('system/user', []);
	$users = is_array($users) ? (isset($users['name']) && !is_array($users['name']) ? [$users] : $users) : [];
	foreach ($users as $u) {
		if (is_array($u) && isset($u['name']) && (string)$u['name'] === $name) {
			$found = $u;
		}
	}
	return $found;
}

/*
 * The account a session belongs to, as passkey owner. For local accounts
 * it is the name the user database resolves the sign-in name to, and ''
 * when it resolves to none: such a session has to pass the passkey step
 * and cannot (fail closed). Remote accounts keep the sign-in name.
 */
function webauthn_session_identity(array $session): string {
	$typed = webauthn_normalize_username($session['Username'] ?? '');
	if ($typed === '' || !webauthn_session_is_local($session)) {
		return $typed;
	}
	$entry = webauthn_local_user($typed);
	return is_array($entry) ? webauthn_normalize_username((string)$entry['name']) : '';
}

/* The PHP session ID a verification is bound to. */
function webauthn_session_sid(): string {
	$sid = session_id();
	if ($sid === '' || $sid === false) {
		$sid = (string)($_COOKIE[session_name()] ?? '');
	}
	return (string)$sid;
}

/* Is this request a password sign-in (pfSense's login form)? */
function webauthn_is_login_post(): bool {
	return isset($_POST['login']) && isset($_POST['usernamefld']);
}

/*
 * May passkeys be stored under this session's name? Not if it holds
 * control or format characters (they would end up in config.xml). For
 * LDAP and RADIUS, not if it contains "\" or "/": the part after them
 * would make the passkey count for another account, although the backend
 * may have authenticated the part before (pfSense signs "x\carol" in as
 * LDAP user x). Such users register under their plain name.
 */
function webauthn_registrable_name(array $session): bool {
	$u = webauthn_session_identity($session);
	if ($u === '' || preg_match('//u', $u) !== 1 || preg_match('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', $u)) {
		return false;
	}
	return webauthn_session_is_local($session) || (!str_contains($u, '\\') && !str_contains($u, '/'));
}

/* Passkeys registered under another spelling of the sign-in name $username (see webauthn_username_keys()). */
function webauthn_case_variant_credentials(string $username): array {
	$out = [];
	$mine = webauthn_username_keys($username, true);
	foreach (webauthn_all_credentials() as $c) {
		$name = webauthn_normalize_username($c['username'] ?? '');
		if ($name !== webauthn_normalize_username($username) &&
		    !empty(array_intersect(webauthn_credential_keys($c), $mine))) {
			$out[] = $c;
		}
	}
	return $out;
}

/*
 * The names a stored passkey stands for: every spelling a backend may
 * take for its owner (see webauthn_username_keys()). Deliberately broad:
 * a passkey that stands for too many names can only refuse someone, one
 * that stands for too few lets another spelling skip the passkey step.
 */
function webauthn_credential_keys(array $c): array {
	return webauthn_username_keys(webauthn_normalize_username($c['username'] ?? ''), false);
}

/* Split a whitespace/comma separated list, dropping empties. */
function webauthn_split_list(?string $s): array {
	return array_values(array_filter(preg_split('/[\s,]+/', (string)$s), 'strlen'));
}

/* Does $ip fall within $cidr (an address or address/prefix, v4 or v6)? */
function webauthn_ip_in_cidr(string $ip, string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$net = @inet_pton($parts[0]);
	$addr = @inet_pton($ip);
	if ($net === false || $addr === false || strlen($net) != strlen($addr)) {
		return false;
	}
	$bits = strlen($addr) * 8;
	if (isset($parts[1])) {
		if (!ctype_digit($parts[1]) || (int)$parts[1] > $bits) {
			return false;
		}
		$prefix = (int)$parts[1];
	} else {
		$prefix = $bits;
	}
	$full = intdiv($prefix, 8);
	if (substr($addr, 0, $full) !== substr($net, 0, $full)) {
		return false;
	}
	$rem = $prefix % 8;
	if ($rem == 0) {
		return true;
	}
	$mask = (0xff << (8 - $rem)) & 0xff;
	return (ord($addr[$full]) & $mask) == (ord($net[$full]) & $mask);
}

function webauthn_ip_in_list(string $ip, array $list): bool {
	foreach ($list as $cidr) {
		if (webauthn_ip_in_cidr($ip, $cidr)) {
			return true;
		}
	}
	return false;
}

/* Is the prefix shorter than /8 (IPv4) or /16 (IPv6)? */
function webauthn_cidr_too_large(string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	if (!isset($parts[1]) || !ctype_digit($parts[1])) {
		return false;
	}
	$bin = @inet_pton($parts[0]);
	return (int)$parts[1] < (($bin !== false && strlen($bin) == 16) ? 16 : 8);
}

function webauthn_valid_cidr(string $cidr): bool {
	$parts = explode('/', $cidr, 2);
	$bin = @inet_pton($parts[0]);
	if ($bin === false) {
		return false;
	}
	return !isset($parts[1]) || (ctype_digit($parts[1]) && (int)$parts[1] <= strlen($bin) * 8);
}

/*
 * Describe where a request came from.
 *
 * $server is $_SERVER. CF-Connecting-IP is only believed when the TCP
 * peer is one of the configured cloudflared addresses; from anyone else
 * it could be forged.
 *
 * Returns:
 *   peer        - the TCP peer pfSense sees (REMOTE_ADDR)
 *   client      - the best-known real client address
 *   via_proxy   - the peer is a configured cloudflared address
 *   proxy_headers - the request carries Cloudflare or other reverse-proxy
 *                   headers, i.e. it was forwarded on someone's behalf
 */
function webauthn_request_source(array $server, array $settings): array {
	$peer = (string)($server['REMOTE_ADDR'] ?? '');
	$via_proxy = ($peer !== '') && webauthn_ip_in_list($peer, webauthn_split_list($settings['trusted_proxies']));
	$cf_ip = trim((string)($server['HTTP_CF_CONNECTING_IP'] ?? ''));
	$client = $peer;
	if ($via_proxy && $cf_ip !== '' && filter_var($cf_ip, FILTER_VALIDATE_IP) !== false) {
		$client = $cf_ip;
	}
	return [
		'peer' => $peer,
		'client' => $client,
		'via_proxy' => $via_proxy,
		'proxy_headers' => isset($server['HTTP_CF_CONNECTING_IP']) || isset($server['HTTP_CF_RAY']) ||
		    isset($server['HTTP_CF_ACCESS_JWT_ASSERTION']) || isset($server['HTTP_X_FORWARDED_FOR']) ||
		    isset($server['HTTP_FORWARDED']) || isset($server['HTTP_X_REAL_IP']),
	];
}

/*
 * May this request skip the WebAuthn step because it comes from a
 * trusted local network?
 *
 * Anything arriving through the tunnel never qualifies, even if
 * cloudflared itself sits inside a trusted network (for example on the
 * LAN or on pfSense at 127.0.0.1): otherwise every Internet user would
 * inherit the LAN's exemption. Forwarded requests are recognised by the
 * configured cloudflared address and, as a fallback when that is not
 * configured, by proxy headers such as X-Forwarded-For.
 */
function webauthn_source_is_trusted_network(array $source, array $settings): bool {
	if ($source['via_proxy'] || $source['proxy_headers'] || $source['peer'] === '') {
		return false;
	}
	return webauthn_ip_in_list($source['peer'], webauthn_split_list($settings['trusted_networks']));
}

/*
 * Decide what the gate does for a password-authenticated session that
 * has not yet passed WebAuthn.
 *   'skip'     - let the request through without WebAuthn
 *   'require'  - show the WebAuthn challenge
 *   'deny'     - user has no passkey and enforcement is on
 */
function webauthn_gate_decision(array $settings, array $source, bool $has_credentials): string {
	if (empty($settings['enable'])) {
		return 'skip';
	}
	if (webauthn_source_is_trusted_network($source, $settings)) {
		return 'skip';
	}
	if ($has_credentials) {
		return 'require';
	}
	return empty($settings['enforce']) ? 'skip' : 'deny';
}

/*
 * Where a GUI session stands with respect to the second factor.
 *   'disabled'  - the second factor is off
 *   'verified'  - passed WebAuthn in this login, recently enough, with a
 *                 passkey that is still registered, for the current RP ID
 *                 and user verification setting
 *   'revoked'   - passed WebAuthn with a passkey that has been removed
 *   'skip'      - exempt for this request (trusted network, or no passkey
 *                 while enforcement is off)
 *   'require'   - must pass WebAuthn now
 *   'deny'      - no passkey and enforcement is on
 * $session is $_SESSION.
 */
function webauthn_session_status(array $settings, array $session, array $source): string {
	if (empty($settings['enable'])) {
		return 'disabled';
	}
	$user = webauthn_session_identity($session);
	if ($user === '') {
		return 'require';
	}
	$state = $session['webauthn'] ?? null;
	if (is_array($state) && ($state['method'] ?? null) === 'webauthn' &&
	    webauthn_normalize_username($state['user'] ?? '') === $user) {
		if (!is_string($state['credential'] ?? null) || webauthn_find_credential($user, $state['credential']) === null) {
			/* Its passkey was removed: the session ends, even if the user
			 * has no passkey left and would otherwise skip the step. */
			return 'revoked';
		}
		if (webauthn_verified_state_valid($state, $settings)) {
			return 'verified';
		}
		/* From another login, too old, or weaker than the settings now
		 * ask for: decide as for a session that never verified. */
	}
	$status = webauthn_gate_decision($settings, $source, webauthn_session_has_credentials($session));
	if ($status === 'skip' && webauthn_session_is_local($session) &&
	    $user !== webauthn_normalize_username($session['Username'] ?? '') &&
	    !webauthn_source_is_trusted_network($source, $settings)) {
		/* The sign-in name is not the account name it resolved to. */
		return 'require';
	}
	return $status;
}

/*
 * Is a stored passkey verification still good? It must belong to this
 * PHP session (pfSense gives every password sign-in a new session ID, so
 * a new sign-in never inherits it), be at most WEBAUTHN_VERIFIED_MAX_AGE
 * old, and match the current RP ID and user verification setting.
 */
function webauthn_verified_state_valid(array $state, array $settings): bool {
	$time = (int)($state['time'] ?? 0);
	$now = time();
	return is_string($state['sid'] ?? null) && hash_equals($state['sid'], webauthn_session_sid()) &&
	    $time > 0 && $time <= $now && $now - $time <= WEBAUTHN_VERIFIED_MAX_AGE &&
	    ($state['rp_id'] ?? null) === webauthn_rp_id($settings) &&
	    (!webauthn_require_uv($settings) || !empty($state['uv']));
}

/* The session state recorded after a successful passkey verification. Call after session_regenerate_id(). */
function webauthn_verified_state(string $user, array $cred, bool $uv, array $settings): array {
	return ['user' => $user, 'method' => 'webauthn', 'credential' => (string)$cred['id'], 'time' => time(),
	    'sid' => webauthn_session_sid(), 'rp_id' => webauthn_rp_id($settings), 'uv' => $uv];
}

/*
 * Does the session's user have passkeys? For remote accounts, another
 * spelling with passkeys counts too: it must not skip the step. Without
 * intl/mbstring other spellings cannot be recognised reliably, so then
 * any passkey at all counts for remote accounts (fail closed).
 */
function webauthn_session_has_credentials(array $session): bool {
	$user = webauthn_session_identity($session);
	if (!empty(webauthn_get_credentials($user))) {
		return true;
	}
	if (webauthn_session_is_local($session)) {
		return false;
	}
	if (!webauthn_unicode_available()) {
		static $warned = false;
		if (!$warned) {
			$warned = true;
			webauthn_log(LOG_WARNING, 'PHP intl/mbstring missing: every passkey counts for every LDAP/RADIUS user');
		}
		return !empty(webauthn_all_credentials());
	}
	return !empty(webauthn_case_variant_credentials($user));
}

/*
 * May this session register a passkey? Once the account (or, for remote
 * accounts, another spelling of it) has a passkey, only a session that
 * signed in with one may add another. Otherwise a password alone, from a
 * trusted network or while enforcement is off, would be enough to enrol
 * an attacker's passkey for later use through the tunnel. While the
 * second factor is off nobody is verified, so then only an admin may.
 */
function webauthn_may_register(array $settings, array $session, array $source, bool $is_admin = false): bool {
	if (!webauthn_session_has_credentials($session)) {
		return true;
	}
	$status = webauthn_session_status($settings, $session, $source);
	return $status === 'verified' || ($status === 'disabled' && $is_admin);
}

function webauthn_rp_id(?array $settings = null): string {
	$settings = $settings ?? webauthn_settings();
	return strtolower(trim($settings['rp_id']));
}

/* Origins accepted in clientDataJSON. Defaults to https://<rp_id>. */
function webauthn_allowed_origins(?array $settings = null): array {
	$settings = $settings ?? webauthn_settings();
	$origins = array_map('webauthn_normalize_origin', webauthn_split_list($settings['origins']));
	if (empty($origins) && webauthn_rp_id($settings) !== '') {
		$origins = ['https://' . webauthn_rp_id($settings)];
	}
	return $origins;
}

function webauthn_require_uv(?array $settings = null): bool {
	$settings = $settings ?? webauthn_settings();
	return $settings['user_verification'] === 'required';
}

/* Validate settings submitted from the GUI. Returns a list of errors. */
function webauthn_validate_settings(array $s): array {
	$errors = [];
	$rp_id = strtolower(trim($s['rp_id'] ?? ''));
	if (!empty($s['enable']) && $rp_id === '') {
		$errors[] = gettext('An RP ID is required when WebAuthn is enabled.');
	}
	if ($rp_id !== '') {
		if (filter_var($rp_id, FILTER_VALIDATE_IP) !== false) {
			$errors[] = gettext('The RP ID must be a domain name; passkeys cannot be bound to an IP address.');
		} elseif (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/', $rp_id)) {
			$errors[] = gettext('The RP ID must be a fully qualified domain name (for example pfsense.example.com or example.com).');
		}
	}
	$origins = webauthn_split_list($s['origins'] ?? '');
	foreach ($origins as $o) {
		if (!webauthn_origin_matches_rp(webauthn_normalize_origin($o), $rp_id)) {
			$errors[] = sprintf(gettext('Origin %1$s must be https:// and its host must be %2$s or a subdomain of it.'),
			    htmlspecialchars($o), htmlspecialchars($rp_id));
		}
	}
	foreach (['trusted_proxies' => gettext('cloudflared source'), 'trusted_networks' => gettext('Trusted network'),
	    'xmlrpc_peers' => gettext('XMLRPC peer')] as $field => $label) {
		foreach (webauthn_split_list($s[$field] ?? '') as $c) {
			if (!webauthn_valid_cidr($c)) {
				$errors[] = sprintf(gettext('%1$s entry %2$s is not a valid IP address or CIDR.'), $label, htmlspecialchars($c));
			}
		}
	}
	/* A cloudflared address inside a trusted network is fine (tunnel
	 * traffic is never exempt), but a huge network (however written, e.g.
	 * /00) would exempt or admit a large part of the Internet. */
	$trusted = webauthn_split_list($s['trusted_networks'] ?? '');
	foreach (['trusted_networks' => gettext('Trusted network'), 'xmlrpc_peers' => gettext('XMLRPC peer')] as $field => $label) {
		foreach (webauthn_split_list($s[$field] ?? '') as $c) {
			if (webauthn_valid_cidr($c) && webauthn_cidr_too_large($c)) {
				$errors[] = sprintf(gettext('%1$s entry %2$s is too large: use at least /8 for IPv4 and /16 for IPv6.'),
				    $label, htmlspecialchars($c));
			}
		}
	}
	/* Without the cloudflared address, tunnel traffic from a LAN host is
	 * only told apart from LAN traffic by its proxy headers. */
	if (!empty($trusted) && empty(webauthn_split_list($s['trusted_proxies'] ?? ''))) {
		$errors[] = gettext('Set the cloudflared source before adding trusted networks, so tunnel traffic can never be mistaken for local traffic.');
	}
	if (!in_array($s['user_verification'] ?? '', ['discouraged', 'preferred', 'required'], true)) {
		$errors[] = gettext('Invalid user verification setting.');
	}
	return $errors;
}

/*
 * Would saving $new lock out the admin saving it, from where they are
 * ($source, under the new settings), given their passkeys $mine? Returns
 * the error message, or null.
 */
function webauthn_settings_lockout_error(array $new, array $source, array $mine): ?string {
	if (empty($new['enable']) || webauthn_source_is_trusted_network($source, $new)) {
		return null;
	}
	if (webauthn_gate_decision($new, $source, !empty($mine)) == 'deny') {
		return gettext('These settings would lock you out of this session: register a passkey for your account, or save from a trusted network.');
	}
	if (!empty($mine) && !in_array(webauthn_rp_id($new), array_column($mine, 'rp_id'), true)) {
		return gettext('None of your passkeys was registered for this RP ID, so you could not sign in again: save from a trusted network, or keep the RP ID.');
	}
	return null;
}

/*
 * Log to syslog with the USER facility and a message format that does
 * not match sshguard's "webConfigurator authentication error" pattern,
 * so WebAuthn failures never add the cloudflared address (shared by all
 * tunnel users) to the GUI lockout table.
 */
function webauthn_log(int $level, string $message, ?array $source = null): void {
	if ($source !== null) {
		$message .= ' from ' . $source['client'];
		if ($source['via_proxy']) {
			$message .= ' (via cloudflared ' . $source['peer'] . ')';
		}
	}
	$message = preg_replace('/[\x00-\x1f\x7f]/', ' ', $message);
	syslog(LOG_USER | $level, 'webauthn: ' . $message);
}

/*
 * $s as one line of plain text for notices, notification e-mails and
 * config history: no control, format (e.g. bidi override) or line/paragraph
 * separator characters, valid UTF-8, at most $max characters. Login names
 * from LDAP/RADIUS can carry arbitrary text after "@".
 */
function webauthn_plain(string $s, int $max = 64): string {
	if (function_exists('mb_check_encoding') ? !mb_check_encoding($s, 'UTF-8') : !preg_match('//u', $s)) {
		$s = function_exists('mb_scrub') ? mb_scrub($s, 'UTF-8') : preg_replace('/[\x80-\xff]/', '?', $s);
	}
	$s = preg_replace('/[\x00-\x1f\x7f]/', ' ', $s);
	$s = preg_replace('/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u', ' ', $s) ?? preg_replace('/[\x80-\xff]/', '?', $s);
	if (function_exists('mb_strlen') && mb_strlen($s, 'UTF-8') > $max) {
		$s = mb_substr($s, 0, $max, 'UTF-8') . '…';
	} elseif (!function_exists('mb_strlen') && strlen($s) > $max) {
		$s = substr($s, 0, $max) . '...';
	}
	return $s;
}

/*
 * Raise a GUI notice (the bell icon; also sent through any configured
 * notification channels such as e-mail) for security-relevant events.
 * Callers quote user-supplied names ("%s"). pfSense escapes notices for
 * HTML itself (file_notice() and head.inc), so this only makes the text
 * plain. With $rate_key, at most one notice per key is raised in
 * WEBAUTHN_NOTICE_INTERVAL seconds.
 */
function webauthn_notice(string $message, ?string $rate_key = null): void {
	if ($rate_key !== null && !webauthn_notice_due($rate_key)) {
		return;
	}
	if (!function_exists('file_notice')) {
		@include_once('notices.inc');
	}
	if (function_exists('file_notice')) {
		file_notice('webauthn', webauthn_plain($message, 400), 'WebAuthn');
	}
}

/* Record that a notice for $key is raised now; false if one was raised recently. */
function webauthn_notice_due(string $key): bool {
	$due = webauthn_with_lock(WEBAUTHN_NOTICE_FILE, function () use ($key) {
		$now = time();
		$data = json_decode((string)@file_get_contents(WEBAUTHN_NOTICE_FILE), true);
		$data = is_array($data) ? $data : [];
		$data = array_filter($data, function ($t) use ($now) {
			return is_int($t) && $t > $now - WEBAUTHN_NOTICE_INTERVAL;
		});
		$k = hash('sha256', $key);
		if (isset($data[$k])) {
			return false;
		}
		$data[$k] = $now;
		if (webauthn_write_json(WEBAUTHN_NOTICE_FILE, $data)) {
			return true;
		}
		/* /conf cannot be written (full disk): rate limit with a marker in
		 * WEBAUTHN_RUN_DIR instead; without one, raise no notice at all
		 * rather than one per request. */
		return webauthn_run_marker_due('notice_' . substr($k, 0, 32));
	}, null);
	return $due ?? webauthn_run_marker_due('notice_' . substr(hash('sha256', $key), 0, 32));
}

/* True (and the marker set) if marker $name in WEBAUTHN_RUN_DIR is absent or older than WEBAUTHN_NOTICE_INTERVAL. */
function webauthn_run_marker_due(string $name): bool {
	$f = WEBAUTHN_RUN_DIR . '/webauthn_' . $name;
	clearstatcache(true, $f);
	if (file_exists($f) && time() - (int)@filemtime($f) < WEBAUTHN_NOTICE_INTERVAL) {
		return false;
	}
	return @touch($f);
}

/*
 * Is $name acceptable as a passkey name? Letters, digits, spaces and
 * . _ ( ) - only, 1 to 64 characters, valid UTF-8: config.xml must stay
 * readable (pfSense writes control characters into it unchanged, which
 * makes the file invalid XML).
 */
function webauthn_valid_passkey_name(string $name): bool {
	return preg_match('//u', $name) === 1 && preg_match('/^[\p{L}\p{N} ._()\-]{1,64}$/u', $name) === 1;
}

/* ---- Credential storage ---- */

/*
 * All stored credentials as a list, without revoked ones. <item> is a
 * pfSense list tag, so it always parses as a list; wrap a bare element
 * anyway in case one was written by hand.
 */
function webauthn_all_credentials(): array {
	$all = config_get_path(WEBAUTHN_CRED_PATH, []);
	if (!is_array($all)) {
		return [];
	}
	if (isset($all['id']) && !is_array($all['id'])) {
		$all = [$all];
	}
	/* A damaged list still lets every passkey count as present (no skipping); webauthn_find_credential() then refuses them all. */
	$revoked = webauthn_revoked_ids() ?? [];
	return array_values(array_filter($all, function ($c) use ($revoked) {
		return is_array($c) && !isset($revoked[(string)($c['id'] ?? '')]);
	}));
}

/*
 * Credentials of $username (all if null). Passkeys registered by a local
 * account record its uid; once that account is deleted and a new one
 * gets the same name, they no longer count (see webauthn_orphaned()).
 */
function webauthn_get_credentials(?string $username = null): array {
	$out = [];
	foreach (webauthn_all_credentials() as $c) {
		if ($username === null || (webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username) &&
		    !webauthn_orphaned($c))) {
			$out[] = $c;
		}
	}
	return $out;
}

/* Was $c registered by a local account that no longer exists (same name, other uid, or gone)? */
function webauthn_orphaned(array $c): bool {
	if (!isset($c['uid']) || $c['uid'] === '') {
		return false;
	}
	$u = webauthn_local_user(webauthn_normalize_username($c['username'] ?? ''));
	return !is_array($u) || (string)($u['uid'] ?? '') !== (string)$c['uid'];
}

/*
 * Change installedpackages/webauthn safely: under our own lock, on the
 * configuration as it is on disk now (pfSense keeps the config as it was
 * when the request started, and write_config() writes all of it, so a
 * change made by a parallel request would otherwise be undone). $change
 * returns false to abort. pfSense's own config lock (/tmp/config.lock) is
 * a different file, taken inside write_config(): no deadlock.
 */
function webauthn_config_update(callable $change, string $desc, ?callable $after = null): bool {
	return webauthn_with_lock(WEBAUTHN_CONFIG_LOCK, function () use ($change, $desc, $after) {
		if (!webauthn_config_reload() || $change() === false) {
			return false;
		}
		if (!is_array(write_config(webauthn_plain($desc, 200)))) {
			return false;
		}
		webauthn_record_config_state();
		/* Still under the lock, so it cannot interleave with another change. */
		return $after === null || $after() !== false;
	}, false);
}

/*
 * Hash of the package's part of a config ($section, default: in memory).
 * Normalised as config.xml stores it: empty lists dropped, values as
 * strings, so a save and its re-read hash alike.
 */
function webauthn_config_hash($section = null): string {
	$norm = function ($v) use (&$norm) {
		if (!is_array($v)) {
			return (string)$v;
		}
		$out = [];
		foreach ($v as $k => $x) {
			$x = $norm($x);
			if ($x !== []) {
				$out[(string)$k] = $x;
			}
		}
		return $out;
	};
	$section = func_num_args() ? $section : config_get_path('installedpackages/webauthn', []);
	return hash('sha256', serialize($norm(is_array($section) ? $section : [])));
}

/* The package's part of config.xml as it is on disk now; null if it cannot be read. */
function webauthn_disk_section(): ?array {
	if (!function_exists('parse_xml_config') || !function_exists('g_get')) {
		return null;
	}
	$parsed = parse_xml_config(g_get('conf_path') . '/config.xml', [g_get('xml_rootobj')]);
	if (!is_array($parsed)) {
		return null;
	}
	$section = $parsed['installedpackages']['webauthn'] ?? [];
	return is_array($section) ? $section : [];
}

/* Remember the package's config as saved now. */
function webauthn_record_config_state(): bool {
	return webauthn_write_json(WEBAUTHN_STATE_FILE, ['hash' => webauthn_config_hash(), 'time' => time()]);
}

/*
 * Did installedpackages/webauthn change since this package last saved it?
 * Other pages save the whole config as it was when their request began,
 * so a save overlapping a passkey or settings change can undo it (removed
 * passkeys stay revoked regardless); a config restore changes it too.
 * Neither can be prevented from here, but neither stays silent: the first
 * request that sees the difference raises a notice and records the new
 * state. Returns true if a difference was found.
 */
function webauthn_check_config_state(): bool {
	$data = json_decode((string)@file_get_contents(WEBAUTHN_STATE_FILE), true);
	if (is_array($data) && ($data['hash'] ?? null) === webauthn_config_hash()) {
		return false;
	}
	/* The state could not be recorded recently (full /conf): do not parse
	 * config.xml under the lock on every request; try again later. */
	$retry = WEBAUTHN_RUN_DIR . '/webauthn_state_retry';
	clearstatcache(true, $retry);
	if (file_exists($retry) && time() - (int)@filemtime($retry) < WEBAUTHN_NOTICE_INTERVAL) {
		return false;
	}
	$changed = webauthn_with_lock(WEBAUTHN_CONFIG_LOCK, function () use ($retry) {
		$data = json_decode((string)@file_get_contents(WEBAUTHN_STATE_FILE), true);
		$known = is_array($data) && isset($data['hash']);
		/* This request may simply have loaded the config before the last
		 * save by this package: compare what is on disk now. */
		$disk = webauthn_disk_section();
		$now = $disk === null ? webauthn_config_hash() : webauthn_config_hash($disk);
		if ($known && $data['hash'] === $now) {
			return false;
		}
		if (!webauthn_write_json(WEBAUTHN_STATE_FILE, ['hash' => $now, 'time' => time()])) {
			@touch($retry);
		}
		return $known;
	}, false);
	if ($changed) {
		webauthn_log(LOG_WARNING, 'passkeys or settings changed outside the WebAuthn page (config restore, or another page saving an older copy)');
		webauthn_notice('The WebAuthn passkeys or settings changed outside System > WebAuthn Passkeys: a config restore, ' .
		    'or another page saving an older copy of the configuration at the same time. Check that the settings and passkeys are as intended.',
		    'config-state');
	}
	return $changed;
}

/*
 * Reload config.xml into memory. Newer pfSense has config_read_file();
 * older versions (2.7.x) only parse_config(), which can die() or restore
 * a backup, so there config.xml is parsed directly. False (abort the
 * change) if the file cannot be read.
 */
function webauthn_config_reload(): bool {
	if (function_exists('config_read_file')) {
		return config_read_file(false, false);
	}
	if (!function_exists('parse_xml_config') || !function_exists('g_get')) {
		return false;
	}
	$parsed = parse_xml_config(g_get('conf_path') . '/config.xml', [g_get('xml_rootobj')]);
	if (!is_array($parsed) || empty($parsed)) {
		return false;
	}
	$GLOBALS['config'] = $parsed;
	return true;
}

/*
 * Store a new passkey. Returns null on success, or an error message.
 * $uid: the pfSense uid of a local account, '' for remote accounts.
 */
function webauthn_add_credential(string $username, string $name, array $reg, string $rp_id, string $uid = ''): ?string {
	$id = webauthn_b64url_encode($reg['credential_id']);
	$error = null;
	$ok = webauthn_config_update(function () use ($username, $name, $reg, $rp_id, $uid, $id, &$error) {
		$all = config_get_path(WEBAUTHN_CRED_PATH, []);
		$all = is_array($all) ? array_values(array_filter(isset($all['id']) && !is_array($all['id']) ? [$all] : $all, 'is_array')) : [];
		$revoked = webauthn_revoked_ids();
		if ($revoked === null) {
			$error = gettext('The list of removed passkeys is damaged; see the system log.');
			return false;
		}
		$own = 0;
		foreach ($all as $i => $c) {
			if (($c['id'] ?? null) === $id) {
				if (!isset($revoked[$id])) {
					$error = gettext('This passkey is already registered.');
					return false;
				}
				/* A revoked record brought back (e.g. by a restore) is replaced. */
				unset($all[$i]);
			} elseif (!isset($revoked[(string)($c['id'] ?? '')]) && !webauthn_orphaned($c) &&
			    webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username)) {
				$own++;
			}
		}
		if ($own >= WEBAUTHN_MAX_CREDENTIALS_PER_USER) {
			$error = sprintf(gettext('An account can have at most %d passkeys.'), WEBAUTHN_MAX_CREDENTIALS_PER_USER);
			return false;
		}
		$all = array_values($all);
		/* Stored before the passkey becomes usable: a counter that cannot
		 * be kept would make clone detection meaningless. */
		if (!webauthn_set_sign_count($id, (int)$reg['sign_count'])) {
			$error = gettext('The signature counter could not be stored.');
			return false;
		}
		$rec = [
			'username' => webauthn_normalize_username($username),
			'name' => $name,
			'id' => $id,
			'alg' => (string)$reg['alg'],
			'publickey' => base64_encode($reg['pem']),
			'rp_id' => $rp_id,
			'created' => (string)time(),
		];
		if ($uid !== '') {
			$rec['uid'] = $uid;
		}
		$all[] = $rec;
		config_set_path(WEBAUTHN_CRED_PATH, $all);
	}, sprintf('WebAuthn: registered passkey "%s" for user "%s"', webauthn_plain($name), webauthn_plain($username)),
	    function () use ($id, &$error) {
		/* Only now, with the record that replaces any revoked one saved (and
		 * still under the lock): lifting the revocation earlier would revive
		 * that old record if the save failed. */
		if (!webauthn_unrevoke($id)) {
			$error = gettext('The passkey was saved but cannot be used yet: the list of removed passkeys could not be updated.');
			return false;
		}
	});
	if (!$ok) {
		return $error ?? gettext('The configuration could not be saved.');
	}
	return null;
}

/*
 * Delete a credential; restrict to $username unless null (admin). Every
 * record with that ID goes, and the ID is revoked first, so it is never
 * accepted again even if the change cannot be saved or a config restore
 * brings it back. Unless $may_remove_last, the account must keep another
 * usable passkey (for the current RP ID). All of it is decided under the
 * config lock on the reloaded config, so parallel removals cannot each
 * leave the other passkey as "the one left". True only if the change was
 * saved and the ID is gone; $error says why not.
 */
function webauthn_delete_credential(string $id, ?string $username = null, bool $may_remove_last = true, ?string &$error = null): bool {
	$error = null;
	$match = function ($c) use ($id, $username) {
		return is_array($c) && ($c['id'] ?? null) === $id && ($username === null ||
		    webauthn_normalize_username($c['username'] ?? '') === webauthn_normalize_username($username));
	};
	$ok = webauthn_config_update(function () use ($id, $username, $may_remove_last, $match, &$error) {
		if (empty(array_filter(webauthn_all_credentials(), $match))) {
			$error = gettext('Passkey not found.');
			return false;
		}
		if (!$may_remove_last && $username !== null) {
			$rp = webauthn_rp_id(webauthn_settings());
			$left = array_filter(webauthn_get_credentials($username), function ($c) use ($id, $rp) {
				return ($c['id'] ?? null) !== $id && ($c['rp_id'] ?? null) === $rp;
			});
			if (empty($left)) {
				$error = gettext('This is your last usable passkey: sign in with it (through a non-trusted path) before removing it, or ask an administrator.');
				return false;
			}
		}
		if (!webauthn_revoke($id)) {
			$error = gettext('The passkey could not be revoked. Check the system log.');
			return false;
		}
		$all = config_get_path(WEBAUTHN_CRED_PATH, []);
		$all = is_array($all) ? (isset($all['id']) && !is_array($all['id']) ? [$all] : $all) : [];
		$keep = [];
		foreach ($all as $c) {
			if (is_array($c) && !$match($c)) {
				$keep[] = $c;
			}
		}
		config_set_path(WEBAUTHN_CRED_PATH, $keep);
	}, 'WebAuthn: removed passkey ' . substr($id, 0, 16), function () use ($id) {
		if (!webauthn_config_reload()) {
			return false;
		}
		foreach ((array)config_get_path(WEBAUTHN_CRED_PATH, []) as $c) {
			if (is_array($c) && ($c['id'] ?? null) === $id) {
				return false;
			}
		}
	});
	if (!$ok) {
		$error = $error ?? gettext('The passkey could not be removed. Check the system log.');
		return false;
	}
	webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id) {
		$data = webauthn_read_counters();
		if (is_array($data) && isset($data[$id])) {
			unset($data[$id]);
			webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
		}
	});
	return true;
}

/* Save the settings under the config lock. */
function webauthn_save_settings(array $new): bool {
	return webauthn_config_update(function () use ($new) {
		config_set_path(WEBAUTHN_CONFIG_PATH, $new);
	}, gettext('WebAuthn: settings changed'));
}

/*
 * Revoked credential IDs as a set (id => time); null if the file exists
 * but cannot be read as such (it is only ever replaced whole, so this
 * means outside damage): then no passkey is accepted (fail closed).
 */
function webauthn_revoked_ids(): ?array {
	$raw = @file_get_contents(WEBAUTHN_REVOKED_FILE);
	if ($raw === false) {
		return file_exists(WEBAUTHN_REVOKED_FILE) ? null : [];
	}
	$data = json_decode($raw, true);
	return is_array($data) ? $data : null;
}

function webauthn_revoke(string $id): bool {
	return webauthn_with_lock(WEBAUTHN_REVOKED_FILE, function () use ($id) {
		$data = webauthn_revoked_ids();
		if ($data === null) {
			return false;
		}
		$data[$id] = time();
		return webauthn_write_json(WEBAUTHN_REVOKED_FILE, $data);
	});
}

/* Registering the same credential ID again makes it valid again (authenticators normally create new IDs). */
function webauthn_unrevoke(string $id): bool {
	return webauthn_with_lock(WEBAUTHN_REVOKED_FILE, function () use ($id) {
		$data = webauthn_revoked_ids();
		if ($data === null) {
			return false;
		}
		if (!isset($data[$id])) {
			return true;
		}
		unset($data[$id]);
		return webauthn_write_json(WEBAUTHN_REVOKED_FILE, $data);
	});
}

/*
 * Signature counters are kept outside config.xml so that every login
 * does not create a configuration revision. A damaged counter file is
 * not read as empty (that would reset every counter): counters are then
 * neither checked nor stored, so passkey sign-ins fail until it is
 * repaired or removed.
 */
function webauthn_read_counters(): ?array {
	$raw = @file_get_contents(WEBAUTHN_COUNTER_FILE);
	if ($raw === false) {
		return file_exists(WEBAUTHN_COUNTER_FILE) ? null : [];
	}
	$data = json_decode($raw, true);
	if (!is_array($data)) {
		static $logged = false;
		if (!$logged) {
			$logged = true;
			webauthn_log(LOG_ERR, WEBAUTHN_COUNTER_FILE . ' is damaged: passkey sign-ins fail until it is repaired or removed');
		}
		return null;
	}
	return $data;
}

function webauthn_get_sign_count(string $id): int {
	return (int)(webauthn_read_counters()[$id] ?? 0);
}

function webauthn_set_sign_count(string $id, int $count): bool {
	return webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id, $count) {
		$data = webauthn_read_counters();
		if ($data === null) {
			return false;
		}
		$data[$id] = $count;
		return webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
	});
}

/*
 * Atomically advance the counter; false if it did not increase or could
 * not be stored. Comparing against the value on disk under the lock means
 * two parallel assertions (a clone and the real key) cannot both pass
 * and leave the counter lower than one of them reported.
 */
function webauthn_advance_sign_count(string $id, int $count): bool {
	return webauthn_with_lock(WEBAUTHN_COUNTER_FILE, function () use ($id, $count) {
		$data = webauthn_read_counters();
		if ($data === null) {
			return false;
		}
		$stored = (int)($data[$id] ?? 0);
		if (($count != 0 || $stored != 0) && $count <= $stored) {
			return false;
		}
		$data[$id] = $count;
		return webauthn_write_json(WEBAUTHN_COUNTER_FILE, $data);
	}, false);
}

/* Run $fn holding an exclusive lock on "$file.lock"; $fail if the lock cannot be taken. */
function webauthn_with_lock(string $file, callable $fn, $fail = false) {
	$old = umask(077);
	$lock = @fopen($file . '.lock', 'c');
	umask($old);
	if ($lock === false) {
		return $fail;
	}
	if (!flock($lock, LOCK_EX)) {
		fclose($lock);
		return $fail;
	}
	try {
		return $fn();
	} finally {
		flock($lock, LOCK_UN);
		fclose($lock);
	}
}

/*
 * Replace $file with $data as JSON through a temp file of this process
 * and rename, so a failed write (e.g. a full disk) never leaves a
 * truncated file behind. The file is mode 0600.
 */
function webauthn_write_json(string $file, array $data): bool {
	$json = json_encode($data);
	if (!is_string($json)) {
		return false;
	}
	$tmp = $file . '.' . getmypid() . '.tmp';
	@unlink($tmp);
	$old = umask(077);
	$fp = @fopen($tmp, 'x');
	umask($old);
	$ok = $fp !== false && fwrite($fp, $json) === strlen($json);
	if ($fp !== false) {
		$ok = fclose($fp) && $ok;
	}
	$ok = $ok && @chmod($tmp, 0600) && @rename($tmp, $file);
	if (!$ok) {
		@unlink($tmp);
	}
	return $ok;
}

/* Find a usable stored credential for $username by its base64url ID. */
function webauthn_find_credential(string $username, string $id): ?array {
	if (webauthn_revoked_ids() === null) {
		static $logged = false;
		if (!$logged) {
			$logged = true;
			webauthn_log(LOG_ERR, WEBAUTHN_REVOKED_FILE . ' is damaged: no passkey is accepted until it is repaired or removed');
		}
		return null;
	}
	foreach (webauthn_get_credentials($username) as $c) {
		if (hash_equals((string)$c['id'], $id)) {
			$c['pem'] = base64_decode($c['publickey']);
			$c['sign_count'] = webauthn_get_sign_count($c['id']);
			return $c;
		}
	}
	return null;
}

/*
 * Challenges are self-contained: random nonce, expiry, and an HMAC that
 * binds them to the PHP session, the user, and the purpose. They are not
 * stored in the session, so loading the page again (another tab, a
 * prefetch, a password manager fetching the page) cannot invalidate a
 * challenge the browser is already using. Each nonce is accepted once.
 *
 *   challenge = nonce(16) || expiry(4, big endian) || hmac(16)
 */
function webauthn_hmac_key(): string {
	$key = @file_get_contents(WEBAUTHN_KEY_FILE);
	if ($key !== false && strlen($key) == 32) {
		return $key;
	}
	/* Create the key through a temp file, so no request ever reads a
	 * half-written key and replaces it. The first writer wins. */
	$key = random_bytes(32);
	$tmp = WEBAUTHN_KEY_FILE . '.' . getmypid() . '.tmp';
	$old = umask(077);
	if (@file_put_contents($tmp, $key) === 32 && !@link($tmp, WEBAUTHN_KEY_FILE)) {
		$existing = @file_get_contents(WEBAUTHN_KEY_FILE);
		if ($existing !== false && strlen($existing) == 32) {
			$key = $existing;
		} else {
			@rename($tmp, WEBAUTHN_KEY_FILE);
		}
	}
	@unlink($tmp);
	umask($old);
	return $key;
}

function webauthn_challenge_mac(string $purpose, string $username, string $payload): string {
	$data = implode("\0", [$purpose, webauthn_session_sid(), webauthn_normalize_username($username), $payload]);
	return substr(hash_hmac('sha256', $data, webauthn_hmac_key(), true), 0, 16);
}

function webauthn_new_challenge(string $purpose, string $username): string {
	$payload = random_bytes(16) . pack('N', time() + WEBAUTHN_CHALLENGE_TTL);
	return $payload . webauthn_challenge_mac($purpose, $username, $payload);
}

/*
 * Check the challenge the browser signed (taken from clientDataJSON):
 * HMAC for this session, user and purpose, and expiry. Returns
 * [challenge, nonce, expires] or null. A challenge expiring further ahead
 * than a fresh one would (the clock went back) is refused too.
 */
function webauthn_parse_challenge(string $purpose, string $username, string $client_data_json, int $now): ?array {
	$cd = json_decode($client_data_json, true);
	try {
		$challenge = webauthn_b64url_decode((string)($cd['challenge'] ?? ''));
	} catch (WebAuthnException $e) {
		return null;
	}
	if (strlen($challenge) != 36) {
		return null;
	}
	$payload = substr($challenge, 0, 20);
	if (!hash_equals(webauthn_challenge_mac($purpose, $username, $payload), substr($challenge, 20))) {
		return null;
	}
	$expires = unpack('N', substr($payload, 16, 4))[1];
	if ($expires < $now || $expires > $now + WEBAUTHN_CHALLENGE_TTL) {
		return null;
	}
	return [$challenge, bin2hex(substr($payload, 0, 16)), $expires];
}

/*
 * Run $verify($challenge) for the challenge in clientDataJSON while
 * holding the used-challenge lock, and record the challenge as used only
 * if $verify returns (an exception aborts without recording it). So only
 * completed ceremonies fill the list, which an attacker without a passkey
 * therefore cannot fill, and one signed response is never accepted twice,
 * not even by two parallel requests. Returns $verify's result, or null if
 * the challenge is forged, expired, for another session/user/purpose,
 * already used, or its use cannot be recorded (fail closed).
 */
function webauthn_use_challenge(string $purpose, string $username, string $client_data_json, callable $verify) {
	$now = time();
	$parsed = webauthn_parse_challenge($purpose, $username, $client_data_json, $now);
	if ($parsed === null) {
		return null;
	}
	[$challenge, $nonce, $expires] = $parsed;
	$who = substr(hash('sha256', webauthn_normalize_username($username)), 0, 16);
	return webauthn_with_lock(WEBAUTHN_USED_FILE, function () use ($challenge, $nonce, $expires, $now, $verify, $who) {
		$used = webauthn_used_nonces($now);
		if ($used === null || isset($used[$nonce]) || count($used) >= WEBAUTHN_MAX_LIVE_NONCES) {
			return null;
		}
		/* Per user too: one account completing ceremonies over and over
		 * only blocks itself, never everyone else's sign-ins. */
		$mine = count(array_filter($used, function ($v) use ($who) {
			return is_array($v) && ($v['u'] ?? null) === $who;
		}));
		if ($mine >= WEBAUTHN_MAX_LIVE_NONCES_PER_USER) {
			return null;
		}
		$result = $verify($challenge);
		$used[$nonce] = ['e' => $expires, 'u' => $who];
		if (!webauthn_write_json(WEBAUTHN_USED_FILE, $used)) {
			throw new WebAuthnException('The used-challenge list could not be written');
		}
		return $result;
	}, null);
}

/* Validate a challenge and record it as used; returns the raw challenge or null (see webauthn_use_challenge()). */
function webauthn_take_challenge(string $purpose, string $username, string $client_data_json): ?string {
	try {
		return webauthn_use_challenge($purpose, $username, $client_data_json, function ($challenge) {
			return $challenge;
		});
	} catch (WebAuthnException $e) {
		return null;
	}
}

/*
 * Unexpired used nonces (nonce => expiry); null when the list cannot be
 * trusted: a damaged list may hold nonces that are still valid, so it is
 * refused until every challenge it could hold has expired. Call with the
 * used-challenge lock held.
 */
function webauthn_used_nonces(int $now): ?array {
	$raw = @file_get_contents(WEBAUTHN_USED_FILE);
	$used = ($raw === false) ? (file_exists(WEBAUTHN_USED_FILE) ? null : []) : json_decode($raw, true);
	if (!is_array($used)) {
		clearstatcache(true, WEBAUTHN_USED_FILE);
		if ($now - (int)@filemtime(WEBAUTHN_USED_FILE) <= WEBAUTHN_CHALLENGE_TTL) {
			return null;
		}
		$used = [];
	}
	/* Entries are ['e' => expiry, 'u' => user hash]; older ones a bare expiry. */
	return array_filter($used, function ($v) use ($now) {
		$exp = is_int($v) ? $v : (is_array($v) && is_int($v['e'] ?? null) ? $v['e'] : 0);
		return $exp >= $now;
	});
}
