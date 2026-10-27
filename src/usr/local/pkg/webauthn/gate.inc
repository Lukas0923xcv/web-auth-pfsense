<?php
/*
 * gate.inc
 *
 * WebAuthn second-factor gate. authgui.inc calls webauthn_gate() right
 * after session_auth() succeeds (see hook.php), so every GUI page
 * requires a verified passkey for sessions that need one.
 *
 * Licensed under the Apache License, Version 2.0.
 */

require_once(__DIR__ . '/webauthn.inc');

function webauthn_gate(): void {
	/* Before the enable check: a stale save switching the second factor off must not go unnoticed. */
	webauthn_check_config_state();
	$settings = webauthn_settings();
	if (empty($settings['enable'])) {
		return;
	}

	phpsession_begin();
	$changed = false;
	/*
	 * A password login on this request starts a new login: it must pass
	 * the passkey step itself. The failure count is kept, so signing in
	 * again cannot reset it and hide failed attempts.
	 */
	if (webauthn_is_login_post() && isset($_SESSION['webauthn'])) {
		unset($_SESSION['webauthn']);
		$changed = true;
	}
	$typed = webauthn_normalize_username($_SESSION['Username'] ?? '');
	$user = webauthn_session_identity($_SESSION);
	$state = $_SESSION['webauthn'] ?? null;
	$source = webauthn_request_source($_SERVER, $settings);
	$decision = webauthn_session_status($settings, $_SESSION, $source);

	if ($decision == 'verified') {
		phpsession_end($changed);
		return;
	}

	if ($user === '') {
		/* A local sign-in name that matches no account: fail closed. */
		webauthn_log(LOG_WARNING, "user '{$typed}' does not resolve to a local account; access refused", $source);
		unset($_SESSION['webauthn'], $_SESSION['page-match']);
		phpsession_end(true);
		webauthn_render_gate_page('deny', $settings, null, '');
		exit;
	}

	if ($decision == 'revoked') {
		webauthn_log(LOG_NOTICE, "session of user '{$user}' ended: the passkey it was verified with was removed", $source);
		webauthn_gate_logout();
	}

	if ($decision == 'skip') {
		$method = webauthn_source_is_trusted_network($source, $settings) ? 'trusted-network' : 'no-credential';
		if (!is_array($state) || ($state['user'] ?? null) !== $user || ($state['method'] ?? null) !== $method) {
			$_SESSION['webauthn'] = ['user' => $user, 'method' => $method];
			webauthn_log(LOG_NOTICE, "user '{$user}' skipped WebAuthn (" .
			    ($method == 'trusted-network' ? 'trusted network' : 'no registered passkey and enforcement off') . ")", $source);
			phpsession_end(true);
		} else {
			phpsession_end($changed);
		}
		return;
	}

	/*
	 * The session is password-authenticated but not yet WebAuthn-verified.
	 * Also drop pfSense's cached page privileges: auth_check.inc (used by
	 * getstats.php, ifstats.php and similar) trusts 'page-match' without
	 * going through authgui.inc, so a session that was exempted on a
	 * trusted network must not keep it when it is used from elsewhere.
	 */
	unset($_SESSION['webauthn'], $_SESSION['page-match']);

	if (isAjax()) {
		phpsession_end(true);
		http_response_code(401);
		echo "SESSION_TIMEOUT";
		exit;
	}

	$action = $_POST['webauthn_action'] ?? '';
	if ($action == 'cancel') {
		webauthn_gate_logout();
	}

	$error = '';
	if ($decision == 'deny') {
		webauthn_log(LOG_WARNING, "user '{$user}' has no registered passkey and enforcement is on; access refused", $source);
		phpsession_end(true);
		webauthn_render_gate_page('deny', $settings, null, '');
		exit;
	}

	$creds = webauthn_get_credentials($user);
	if (empty($creds)) {
		/* Only another spelling of this LDAP/RADIUS username (case,
		 * "@domain", ...) has passkeys. They belong to that exact name. */
		webauthn_log(LOG_WARNING, "user '{$user}' has no passkey, but another spelling of the username does; access refused", $source);
		phpsession_end(true);
		webauthn_render_gate_page('case', $settings, null, '');
		exit;
	}

	if ($action == 'assert') {
		$result = webauthn_gate_check_assertion($user, $settings);
		if (is_array($result)) {
			session_regenerate_id(true);
			$_SESSION['webauthn'] = webauthn_verified_state($user, $result, !empty($result['uv']), $settings);
			unset($_SESSION['webauthn_failures']);
			webauthn_log(LOG_NOTICE, "user '{$user}' verified with passkey", $source);
			phpsession_end(true);
			header('Location: ' . webauthn_safe_redirect($_SERVER['REQUEST_URI'] ?? '/'));
			exit;
		}
		$failures = (int)($_SESSION['webauthn_failures'] ?? 0) + 1;
		$_SESSION['webauthn_failures'] = $failures;
		webauthn_log(LOG_WARNING, "passkey verification failed for user '{$user}' ({$failures}/" . WEBAUTHN_MAX_FAILURES . "): {$result}", $source);
		if ($failures >= WEBAUTHN_MAX_FAILURES) {
			webauthn_log(LOG_WARNING, "too many passkey failures for user '{$user}'; session ended", $source);
			webauthn_notice(sprintf('%d failed passkey attempts for user "%s" from %s after a correct password. ' .
			    'If this was not you, change the password.', $failures, webauthn_plain($user), $source['client']), 'failures:' . $user);
			webauthn_gate_logout();
		}
		$error = gettext('Passkey verification failed. Try again.');
	}

	/*
	 * The browser checks that it is on an allowed origin before starting
	 * the ceremony. The Host header pfSense receives cannot be used for
	 * that: cloudflared may rewrite it to the origin service address.
	 */
	$options = [
		'challenge' => webauthn_b64url_encode(webauthn_new_challenge('login', $user)),
		'rpId' => webauthn_rp_id($settings),
		'timeout' => 120000,
		'userVerification' => $settings['user_verification'],
		'allowCredentials' => array_map(function ($c) {
			return ['type' => 'public-key', 'id' => $c['id']];
		}, $creds),
		'origins' => webauthn_allowed_origins($settings),
	];
	phpsession_end(true);
	webauthn_render_gate_page('challenge', $settings, $options, $error);
	exit;
}

/*
 * Returns the verified credential (with 'uv' => bool) on success, or an
 * error string. Session must be open. The challenge counts as used only
 * if the whole check succeeds (see webauthn_use_challenge()).
 */
function webauthn_gate_check_assertion(string $user, array $settings) {
	try {
		$client_data = webauthn_b64url_decode((string)($_POST['client_data'] ?? ''));
		$authenticator_data = webauthn_b64url_decode((string)($_POST['authenticator_data'] ?? ''));
		$signature = webauthn_b64url_decode((string)($_POST['signature'] ?? ''));
		$id = (string)($_POST['credential_id'] ?? '');
		$cred = webauthn_use_challenge('login', $user, $client_data,
		    function ($challenge) use ($user, $settings, $client_data, $authenticator_data, $signature, $id) {
			$cred = webauthn_find_credential($user, $id);
			if ($cred === null) {
				throw new WebAuthnException('unknown credential');
			}
			if (($cred['rp_id'] ?? '') !== webauthn_rp_id($settings)) {
				throw new WebAuthnException('credential was registered for RP ID ' . ($cred['rp_id'] ?? '?'));
			}
			$count = webauthn_verify_assertion($cred, $client_data, $authenticator_data, $signature, $challenge,
			    webauthn_rp_id($settings), webauthn_allowed_origins($settings), webauthn_require_uv($settings), $info);
			if (!webauthn_advance_sign_count($cred['id'], $count)) {
				throw new WebAuthnException('Signature counter did not increase or could not be stored; the authenticator may be cloned');
			}
			$cred['uv'] = !empty($info['uv']);
			return $cred;
		});
		return is_array($cred) ? $cred : 'challenge invalid, expired or already used';
	} catch (WebAuthnException $e) {
		return $e->getMessage();
	}
}

/* End the session entirely and send the browser to the login form. */
function webauthn_gate_logout(): void {
	$_SESSION = [];
	if (isset($_COOKIE[session_name()])) {
		setcookie(session_name(), '', time() - 42000, '/');
	}
	phpsession_destroy();
	header('Location: /');
	exit;
}

/* Only allow local absolute paths as redirect targets. */
function webauthn_safe_redirect(string $uri): string {
	if ($uri === '' || $uri[0] !== '/' || str_starts_with($uri, '//') || str_contains($uri, '\\') ||
	    preg_match('/[\x00-\x1f]/', $uri)) {
		return '/';
	}
	return $uri;
}

function webauthn_render_gate_page(string $mode, array $settings, ?array $options, string $error): void {
	$origins = webauthn_allowed_origins($settings);
	$logincss = '#1e3f75';
	$user_settings = get_user_settings('');
	if (isset($user_settings['webgui']['logincss']) && strlen($user_settings['webgui']['logincss']) == 6 &&
	    ctype_xdigit($user_settings['webgui']['logincss'])) {
		$logincss = '#' . $user_settings['webgui']['logincss'];
	}
	header('Cache-Control: no-cache, no-store, must-revalidate');
?>
<!DOCTYPE html>
<html lang="en">
	<head>
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<link rel="stylesheet" href="/vendor/bootstrap/css/bootstrap.min.css" type="text/css">
		<link rel="stylesheet" href="/css/login.css" type="text/css">
		<title><?=htmlspecialchars(g_get('product_label'))?> - <?=gettext('Passkey')?></title>
	</head>
	<body id="login">
		<div id="total">
			<header>
				<div id="headerrow">
					<div class="row">
						<div class="col-sm-4">
							<div id="logodiv" style="text-align:center" class="nowarning">
								<?php include("/usr/local/www/logo.svg"); ?>
							</div>
						</div>
						<div class="col-sm-4 nowarning msgbox text-center text-danger">
							<h4 id="webauthn-error"><?=htmlspecialchars($error)?></h4>
						</div>
						<div class="col-sm-4 nowarning msgbox text-center">
							<span id="hostspan"><h4><?=htmlspecialchars($_SESSION['Username'] ?? '')?></h4></span>
						</div>
					</div>
				</div>
			</header>

			<div style="background: <?=$logincss?>;" class="pagebody">
				<div class="col-sm-4"></div>
				<div class="col-sm-4 offset-md-4 logoCol">
					<div class="loginCont center-block">
						<form method="post" class="login" id="webauthn-form">
							<p class="form-title"><?=gettext('Passkey verification')?></p>
<?php if ($mode == 'challenge'): ?>
							<input type="hidden" name="webauthn_action" id="webauthn_action" value="assert" />
							<input type="hidden" name="credential_id" id="credential_id" />
							<input type="hidden" name="client_data" id="client_data" />
							<input type="hidden" name="authenticator_data" id="authenticator_data" />
							<input type="hidden" name="signature" id="signature" />
							<div id="webauthn-ready">
								<p style="color:#fff"><?=gettext('Confirm your sign-in with a registered passkey or security key.')?></p>
								<button type="button" id="webauthn-go" class="btn btn-success btn-sm"
									data-options="<?=htmlspecialchars(json_encode($options))?>"><?=gettext('Use passkey')?></button>
							</div>
							<div id="webauthn-wronghost" style="display:none">
								<p style="color:#fff"><?=gettext('Passkeys only work on a configured hostname, not on an IP address or other name. Open the GUI at:')?></p>
								<ul style="color:#fff">
<?php foreach ($origins as $o): ?>
									<li><a style="color:#fff;text-decoration:underline" href="<?=htmlspecialchars($o)?>/"><?=htmlspecialchars($o)?></a></li>
<?php endforeach; ?>
								</ul>
							</div>
<?php elseif ($mode == 'case'): ?>
							<input type="hidden" name="webauthn_action" value="cancel" />
							<p style="color:#fff"><?=gettext('The passkeys for this account are registered under another spelling of the username (for example different capitals or without a @domain suffix). Sign out, then sign in with the username exactly as it was registered.')?></p>
<?php else: ?>
							<input type="hidden" name="webauthn_action" value="cancel" />
							<p style="color:#fff"><?=gettext('This account has no registered passkey, and a passkey is required from this network. Register one from a trusted network first.')?></p>
<?php endif; ?>
							<button type="submit" class="btn btn-default btn-sm" onclick="document.getElementById('webauthn_action') && (document.getElementById('webauthn_action').value='cancel');"><?=gettext('Sign out')?></button>
						</form>
					</div>
				</div>
				<div class="col-sm-4"></div>
			</div>
		</div>
<?php if ($mode == 'challenge'): ?>
		<script src="/webauthn/webauthn.js?v=<?=@filemtime('/usr/local/www/webauthn/webauthn.js')?>"></script>
		<script>webauthnLoginInit();</script>
<?php endif; ?>
	</body>
</html>
<?php
}

/*
 * Called from the auth_check.inc hook. pfSense's lightweight auth check
 * accepts the session's cached page privileges without authgui.inc;
 * allow that only when the gate would let this session through now.
 */
function webauthn_cached_privileges_allowed(): bool {
	$settings = webauthn_settings();
	if (empty($settings['enable'])) {
		return true;
	}
	if (webauthn_is_login_post()) {
		/* A password login goes through authgui.inc and the gate. */
		return false;
	}
	@phpsession_begin();
	$session = is_array($_SESSION ?? null) ? $_SESSION : [];
	$status = webauthn_session_status($settings, $session, webauthn_request_source($_SERVER, $settings));
	@phpsession_end();
	return in_array($status, ['verified', 'skip'], true);
}
