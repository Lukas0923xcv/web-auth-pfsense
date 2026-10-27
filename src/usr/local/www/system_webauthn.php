<?php
/*
 * system_webauthn.php
 *
 * Passkey (WebAuthn) management and settings for the GUI second factor.
 *
 * Licensed under the Apache License, Version 2.0.
 */

##|+PRIV
##|*IDENT=page-system-webauthn
##|*NAME=System: WebAuthn Passkeys
##|*DESCR=Allow access to the 'System: WebAuthn Passkeys' page.
##|*MATCH=system_webauthn.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/webauthn/webauthn.inc");

/* page-all ("*") holders administer everyone's passkeys and the settings. */
$is_admin = in_array('*', $allowedpages);
$tab = ($is_admin && ($_REQUEST['tab'] ?? '') == 'settings') ? 'settings' : 'passkeys';
$settings = webauthn_settings();
$source = webauthn_request_source($_SERVER, $settings);
phpsession_begin();
/* The account passkeys belong to ('' for a local name that resolves to no account). */
$username = webauthn_session_identity($_SESSION);
/* For local accounts the uid is stored too, so a new account with the same name does not inherit them. */
$local_entry = webauthn_session_is_local($_SESSION) ? webauthn_local_user($username) : null;
$uid = is_array($local_entry) ? (string)($local_entry['uid'] ?? '') : '';
/* A user who already has a passkey may only add another from a session verified with one. */
$may_register = $username !== '' && webauthn_may_register($settings, $_SESSION, $source, $is_admin);
phpsession_end();
$input_errors = [];
$savemsg = '';
if (isset($_GET['registered'])) {
	$savemsg = sprintf(gettext('Passkey "%s" registered.'), htmlspecialchars((string)$_GET['registered']));
} elseif (isset($_GET['removed'])) {
	$savemsg = gettext('Passkey removed.');
}

if ($_POST['act'] == 'register') {
	phpsession_begin();
	try {
		$client_data = webauthn_b64url_decode((string)$_POST['reg_client_data']);
		$attestation = webauthn_b64url_decode((string)$_POST['reg_attestation']);
	} catch (WebAuthnException $e) {
		$client_data = $attestation = '';
	}
	$name = trim((string)$_POST['passkey_name']);
	if ($username === '') {
		$input_errors[] = gettext('Your account could not be found in the user database.');
	} elseif (!webauthn_registrable_name($_SESSION)) {
		$input_errors[] = gettext('Passkeys cannot be registered under this spelling of your username (it contains a backslash or a slash). Sign in with your plain account name, then register.');
	} elseif (!$may_register) {
		$input_errors[] = gettext('You already have a passkey: sign in with it (through a non-trusted path) before adding another.');
	} elseif (!webauthn_valid_passkey_name($name)) {
		$input_errors[] = gettext('Enter a passkey name of up to 64 characters: letters, digits, spaces and . _ ( ) - only.');
	} elseif (webauthn_rp_id($settings) === '') {
		$input_errors[] = gettext('Configure an RP ID on the Settings tab first.');
	} else {
		try {
			/* The challenge counts as used once the response verified (per-account limit), before
			 * the config is saved: saving must not hold the lock every sign-in needs. */
			$reg = webauthn_use_challenge('register', $username, $client_data, function ($challenge) use ($client_data, $attestation, $settings) {
				return webauthn_verify_registration($client_data, $attestation, $challenge, webauthn_rp_id($settings),
				    webauthn_allowed_origins($settings), webauthn_require_uv($settings));
			});
			if ($reg === null) {
				throw new WebAuthnException(gettext('The registration request expired or was already used. Try again.'));
			}
			$error = webauthn_add_credential($username, $name, $reg, webauthn_rp_id($settings), $uid);
			if ($error !== null) {
				throw new WebAuthnException($error);
			}
			/* Holding a passkey just proven to the server satisfies the gate; new session ID as after a passkey sign-in. */
			session_regenerate_id(true);
			$_SESSION['webauthn'] = webauthn_verified_state($username, ['id' => webauthn_b64url_encode($reg['credential_id'])],
			    !empty($reg['uv']), $settings);
			webauthn_log(LOG_NOTICE, "user '{$username}' registered passkey '{$name}'", $source);
			webauthn_notice(sprintf('Passkey "%s" was registered for user "%s" from %s.', $name, $username, $source['client']));
			phpsession_end(true);
			/* Redirect so a reload does not resubmit the used challenge. */
			header('Location: system_webauthn.php?registered=' . urlencode($name));
			exit;
		} catch (WebAuthnException $e) {
			webauthn_log(LOG_WARNING, "passkey registration failed for user '{$username}': " . $e->getMessage(), $source);
			$input_errors[] = gettext('Passkey registration failed: ') . htmlspecialchars($e->getMessage());
		}
	}
	phpsession_end(true);
} elseif ($_POST['act'] == 'delete') {
	$id = (string)$_POST['id'];
	phpsession_begin();
	$verified = webauthn_session_status($settings, $_SESSION, $source) === 'verified';
	phpsession_end();
	$delete_error = null;
	if (!$is_admin && $username === '') {
		$input_errors[] = gettext('Passkey not found.');
	} elseif (webauthn_delete_credential($id, $is_admin ? null : $username, $is_admin || $verified, $delete_error)) {
		webauthn_log(LOG_NOTICE, "user '{$username}' removed passkey " . webauthn_plain($id, 200), $source);
		webauthn_notice(sprintf('A passkey was removed by user "%s" from %s.', $username, $source['client']));
		header('Location: system_webauthn.php?removed=1');
		exit;
	} else {
		$input_errors[] = $delete_error;
	}
} elseif ($_POST['save'] && $is_admin) {
	$new = [
		'enable' => isset($_POST['enable']) ? 'yes' : '',
		'rp_id' => strtolower(trim((string)$_POST['rp_id'])),
		'origins' => implode("\n", array_map('webauthn_normalize_origin', webauthn_split_list($_POST['origins']))),
		'trusted_proxies' => implode(' ', webauthn_split_list($_POST['trusted_proxies'])),
		'trusted_networks' => implode(' ', webauthn_split_list($_POST['trusted_networks'])),
		'user_verification' => (string)$_POST['user_verification'],
		'enforce' => isset($_POST['enforce']) ? 'yes' : '',
		'xmlrpc_peers' => implode(' ', webauthn_split_list($_POST['xmlrpc_peers'])),
	];
	$input_errors = webauthn_validate_settings($new);
	if (empty($input_errors)) {
		$lockout = webauthn_settings_lockout_error($new, webauthn_request_source($_SERVER, $new), webauthn_get_credentials($username));
		if ($lockout !== null) {
			$input_errors[] = $lockout;
		}
	}
	if (empty($input_errors) && !webauthn_save_settings($new)) {
		$input_errors[] = gettext('The settings could not be saved.');
	}
	if (empty($input_errors)) {
		$settings = webauthn_settings();
		$source = webauthn_request_source($_SERVER, $settings);
		$savemsg = gettext('Settings saved.');
		webauthn_log(LOG_NOTICE, "user '{$username}' changed WebAuthn settings (enable=" . ($new['enable'] ? 'yes' : 'no') .
		    ", enforce=" . ($new['enforce'] ? 'yes' : 'no') . ")", $source);
		webauthn_notice(sprintf('WebAuthn settings were changed by user "%s" from %s (enabled: %s, enforced: %s).',
		    $username, $source['client'], $new['enable'] ? 'yes' : 'no', $new['enforce'] ? 'yes' : 'no'));
	} else {
		$settings = array_merge($settings, $new);
	}
}

/* Registration options for this page load. */
$reg_options = null;
if ($tab == 'passkeys' && webauthn_rp_id($settings) !== '' && $may_register) {
	phpsession_begin();
	$reg_options = [
		'challenge' => webauthn_b64url_encode(webauthn_new_challenge('register', $username)),
		'rp' => ['id' => webauthn_rp_id($settings), 'name' => g_get('product_label') . ' ' . config_get_path('system/hostname')],
		'user' => [
			'id' => webauthn_b64url_encode(hash('sha256', 'pfsense-webauthn:' . $username, true)),
			'name' => $username,
			'displayName' => $username,
		],
		'algs' => webauthn_supported_algs(),
		'timeout' => 120000,
		'userVerification' => $settings['user_verification'],
		'exclude' => array_column(webauthn_get_credentials($username), 'id'),
		/* Checked in the browser; the Host header may be rewritten by cloudflared. */
		'origins' => webauthn_allowed_origins($settings),
	];
	phpsession_end();
}

$pgtitle = [gettext('System'), gettext('WebAuthn Passkeys')];
include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}
if ($savemsg) {
	print_info_box($savemsg, 'success');
}

$tab_array = [[gettext('Passkeys'), $tab == 'passkeys', 'system_webauthn.php']];
if ($is_admin) {
	$tab_array[] = [gettext('Settings'), $tab == 'settings', 'system_webauthn.php?tab=settings'];
}
display_top_tabs($tab_array);

if ($tab == 'passkeys'):
	if (empty($settings['enable'])) {
		print_info_box(gettext('The WebAuthn second factor is disabled. A first passkey can still be registered; further ones only by an administrator.'), 'warning', false);
	}
	$creds = $is_admin ? webauthn_get_credentials() : webauthn_get_credentials($username);
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('Registered passkeys')?></h2></div>
	<div class="panel-body table-responsive">
		<table class="table table-striped table-hover">
			<thead><tr>
				<th><?=gettext('User')?></th><th><?=gettext('Name')?></th><th><?=gettext('RP ID')?></th>
				<th><?=gettext('Registered')?></th><th><?=gettext('Actions')?></th>
			</tr></thead>
			<tbody>
<?php foreach ($creds as $c): ?>
				<tr>
					<td><?=htmlspecialchars($c['username'])?><?=webauthn_orphaned($c) ? ' <span class="text-danger">(' . gettext('belongs to a deleted account') . ')</span>' : ''?></td>
					<td><?=htmlspecialchars($c['name'])?></td>
					<td><?=htmlspecialchars($c['rp_id'])?><?=($c['rp_id'] !== webauthn_rp_id($settings)) ? ' <span class="text-danger">(' . gettext('does not match current RP ID') . ')</span>' : ''?></td>
					<td><?=htmlspecialchars(date('Y-m-d H:i', (int)$c['created']))?></td>
					<td>
						<form method="post" style="display:inline">
							<input type="hidden" name="act" value="delete" />
							<input type="hidden" name="id" value="<?=htmlspecialchars($c['id'])?>" />
							<button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('<?=gettext('Remove this passkey?')?>');">
								<i class="fa-solid fa-trash-can icon-embed-btn"></i><?=gettext('Remove')?>
							</button>
						</form>
					</td>
				</tr>
<?php endforeach; ?>
			</tbody>
		</table>
	</div>
</div>

<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=sprintf(gettext('Register a passkey for %s'), htmlspecialchars($username))?></h2></div>
	<div class="panel-body">
<?php if (webauthn_rp_id($settings) === ''): ?>
		<p><?=gettext('Set the RP ID on the Settings tab first.')?></p>
<?php elseif (!$may_register): ?>
		<p><?=gettext('You already have a passkey. To add another, sign in through the passkey step first (for example through the tunnel, not from a trusted network), then come back here.')?></p>
<?php else: ?>
		<p id="webauthn-wronghost" class="text-danger" style="display:none"><?=gettext('Passkeys can only be registered when the GUI is opened on one of the allowed origins:')?>
			<?=htmlspecialchars(implode(', ', webauthn_allowed_origins($settings)))?></p>
		<p id="webauthn-error" class="text-danger"></p>
		<form method="post" id="webauthn-register-form" class="form-inline">
			<input type="hidden" name="act" value="register" />
			<input type="hidden" name="reg_client_data" id="reg_client_data" />
			<input type="hidden" name="reg_attestation" id="reg_attestation" />
			<input type="text" class="form-control" name="passkey_name" id="passkey_name" maxlength="64" placeholder="<?=gettext('Name, e.g. YubiKey or iPhone')?>" />
			<button type="button" class="btn btn-success" id="webauthn-register" data-options="<?=htmlspecialchars(json_encode($reg_options))?>">
				<i class="fa-solid fa-key icon-embed-btn"></i><?=gettext('Register passkey')?>
			</button>
		</form>
<?php endif; ?>
	</div>
</div>
<script src="/webauthn/webauthn.js?v=<?=@filemtime('/usr/local/www/webauthn/webauthn.js')?>"></script>
<script>webauthnRegisterInit();</script>
<?php
else:
	$remote_auth = array_filter(config_get_path('system/authserver', []), function ($a) {
		return is_array($a) && in_array($a['type'] ?? '', ['ldap', 'radius'], true);
	});
	if (!empty($remote_auth) && empty($settings['enforce'])) {
		print_info_box(gettext('LDAP or RADIUS servers are configured and Enforce is off. Such servers may accept other spellings ' .
		    'of a username than the one a passkey was registered for. Turn Enforce on, so every account without a passkey is refused.'), 'warning', false);
	}
	$form = new Form();
	$form->addGlobal(new Form_Input('tab', null, 'hidden', 'settings'));

	$section = new Form_Section('WebAuthn second factor');
	$section->addInput(new Form_Checkbox('enable', 'Enable', 'Require a passkey after the password for GUI logins', !empty($settings['enable'])));
	$section->addInput(new Form_Input('rp_id', '*RP ID', 'text', $settings['rp_id'], ['placeholder' => 'pfsense.example.com']))
	    ->setHelp('Relying Party ID: the public hostname (e.g. pfsense.example.com) or a parent domain of it ' .
		'(e.g. example.com). With a parent domain one passkey works on every hostname under it, for example the ' .
		'public hostname and a LAN hostname. Changing it invalidates existing passkeys.');
	$section->addInput(new Form_Textarea('origins', 'Allowed origins', $settings['origins']))
	    ->setHelp('One per line, e.g. https://pfsense.example.com. Each must be https and under the RP ID. ' .
		'These come from the public hostname, not from what pfSense detects locally, since TLS terminates at Cloudflare. ' .
		'Empty means https://&lt;RP ID&gt;. Add a LAN hostname here (e.g. https://pfsense.lan.example.com) to use passkeys on the LAN too.');
	$section->addInput(new Form_Select('user_verification', 'User verification', $settings['user_verification'], [
		'discouraged' => 'Discouraged (presence only)',
		'preferred' => 'Preferred',
		'required' => 'Required (PIN / biometric)',
	]));
	$section->addInput(new Form_Checkbox('enforce', 'Enforce', 'Refuse users without a registered passkey (except from trusted networks)', !empty($settings['enforce'])))
	    ->setHelp('When unchecked, users without a passkey log in with the password only.');
	$form->add($section);

	$section = new Form_Section('Access path');
	$section->addInput(new Form_Input('trusted_proxies', 'cloudflared source', 'text', $settings['trusted_proxies'], ['placeholder' => '127.0.0.1']))
	    ->setHelp('Space separated IPs/CIDRs that cloudflared connects from. Only from these is CF-Connecting-IP trusted ' .
		'(for logging the real client address), and requests from them never get the trusted-network exemption.');
	$section->addInput(new Form_Input('trusted_networks', 'Trusted networks', 'text', $settings['trusted_networks'], ['placeholder' => '192.168.1.0/24']))
	    ->setHelp('Space separated source networks that skip the WebAuthn step (local fallback, e.g. reaching the GUI by LAN IP). ' .
		'Tunnel traffic is never exempt, even if cloudflared runs inside one of these networks.');
	$section->addInput(new Form_Input('xmlrpc_peers', 'XMLRPC peers', 'text', $settings['xmlrpc_peers'], ['placeholder' => '10.10.10.2']))
	    ->setHelp('Space separated IPs/CIDRs allowed to use XMLRPC (HA configuration sync) while WebAuthn is enabled, ' .
		'in addition to the trusted networks. Enter the HA partner\'s sync interface address. XMLRPC authenticates ' .
		'with a password only, so it is refused from every other host.');
	$form->add($section);
	print $form;

	$trusted = webauthn_source_is_trusted_network($source, $settings);
	$althosts = webauthn_split_list(config_get_path('system/webgui/althostnames', ''));
	$missing = [];
	foreach (webauthn_allowed_origins($settings) as $o) {
		$h = parse_url($o, PHP_URL_HOST);
		if ($h && !in_array($h, $althosts) && strcasecmp($h, config_get_path('system/hostname') . '.' . config_get_path('system/domain')) != 0) {
			$missing[] = $h;
		}
	}
?>
<div class="panel panel-default">
	<div class="panel-heading"><h2 class="panel-title"><?=gettext('This request')?></h2></div>
	<div class="panel-body">
		<dl class="dl-horizontal">
			<dt><?=gettext('Host')?></dt><dd><?=htmlspecialchars($_SERVER['HTTP_HOST'])?></dd>
			<dt><?=gettext('TCP peer')?></dt><dd><?=htmlspecialchars($source['peer'])?></dd>
			<dt><?=gettext('CF-Connecting-IP')?></dt><dd><?=htmlspecialchars($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '-')?></dd>
			<dt><?=gettext('From cloudflared')?></dt><dd><?=$source['via_proxy'] ? gettext('yes') : gettext('no')?></dd>
			<dt><?=gettext('Client address')?></dt><dd><?=htmlspecialchars($source['client'])?></dd>
			<dt><?=gettext('Trusted network')?></dt><dd><?=$trusted ? gettext('yes (WebAuthn skipped)') : gettext('no')?></dd>
		</dl>
<?php if ($source['proxy_headers'] && !$source['via_proxy']): ?>
		<p class="text-warning"><?=sprintf(gettext('This request carries proxy headers but %s is not a configured cloudflared source, so CF-Connecting-IP is ignored. Add it if this is cloudflared.'), htmlspecialchars($source['peer']))?></p>
<?php endif; ?>
<?php if (!empty($missing)): ?>
		<p class="text-warning"><?=sprintf(gettext('Add %s to System > Advanced > Admin Access > Alternate Hostnames, or the DNS rebind and HTTP_REFERER checks will reject it.'), htmlspecialchars(implode(' ', $missing)))?></p>
<?php endif; ?>
	</div>
</div>
<?php
endif;
?>
<p class="text-muted"><?=sprintf(gettext('pfSense WebAuthn Passkeys, version %s'), htmlspecialchars(webauthn_version()))?></p>
<?php
include("foot.inc");
