<?php

$params = get_input('params');
$plugin_id = get_input('plugin_id');
$user_guid = get_input('user_guid', elgg_get_logged_in_user_guid());
$plugin = elgg_get_plugin_from_id($plugin_id);
$user = get_entity($user_guid);

foreach ($params as $k => $v) {
	// Save
	$result = $plugin->setUserSetting($k, $v, $user->guid);

	// Error?
	if (!$result) {
		register_error(elgg_echo('plugins:usersettings:save:fail', array($plugin_name)));
		forward(REFERER);
	}
}

if ($params['public_key'] && $params['private_key']) {

    $public_key = $params['public_key'];
    $private_key = $params['private_key'];
    
    // Save key on keyring
    $gpg = new \gnupg();

    $pub = $gpg->import($public_key);
    $pri = $gpg->import($private_key);

    error_log("PUBLIC: " . print_r($pub, true));
    error_log("PRIVATE: " . print_r($pri, true));

    // Save public key against user
    $user->pgp_public_key = $public_key;
    $user->pgp_private_key = $private_key;

    if ((!$pub['fingerprint']) || (!$pri['fingerprint']))
	throw new \Exception("Public and/or private key import failed, sorry!");

    $user->pgp_publickey_fingerprint = $pub['fingerprint'];
    $user->pgp_privatekey_fingerprint = $pri['fingerprint'];

    if ((!$user->pgp_publickey_fingerprint) || (!$user->pgp_privatekey_fingerprint))
	throw new \Exception("Problem saving fingerprints");

    $user->save();
}

	
system_message(elgg_echo('plugins:usersettings:save:ok', array($plugin_name)));
forward(REFERER);