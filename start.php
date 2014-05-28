<?php

/**
 * OpenPGP Signin.
 * 
 * Open PGP signin support for Elgg (based on the one I wrote for Idno)
 * 
 * TODO: 
 *  * Header 
 *  * PGP endpoint
 *  * Save key
 *  * Signin
 * 
 *
 * @licence GNU Public License version 2
 * @link https://github.com/mapkyca/elgg-openpgp-signin
 * @link http://www.marcus-povey.co.uk
 * @author Marcus Povey <marcus@marcus-povey.co.uk>
 */
elgg_register_event_handler('init', 'system', function() {

    // Register libraries
    elgg_register_library('openpgp-signin', dirname(__FILE__) . '/lib/openpgp-signin.php');
    
    // Register javascript
    elgg_register_js('openpgpsignin', elgg_get_site_url() . 'mod/elgg-openpgp-signin/vendor/openpgp.min.js');

    // Signature specified on any page, grab it and save it
    if (isset($_REQUEST['signature'])) {
	error_log("Ooo... we have a signature, saving in session for later...");
	$_SESSION['_PGP_SIGNATURE'] = $_REQUEST['signature'];
	error_log("Signature is: {$_SESSION['_PGP_SIGNATURE']}");
    }

    try {

	// Log user in based on their signature (if there is no logged in user, and signature present in session
	if (isset($_SESSION['_PGP_SIGNATURE']) && (!elgg_get_logged_in_user_entity())) {

	    $signature = $_SESSION['_PGP_SIGNATURE'];

	    $user_id = null;
	    if (preg_match("/(https?:\/\/[^\s]+)/", $signature, $matches))
		$user_id = $matches[1];

	    if ($user_id) {

		$gpg = new \gnupg();

		$signature = substr($signature, strpos($signature, '-----BEGIN PGP SIGNATURE-----')); // GPG verify won't take the full sig, so only return the appropriate bit

		if ($info = $gpg->verify($signature, false)) {

		    if (isset($info[0]))
			$info = $info[0];

		    error_log("Signature verified as : " . print_r($info, true));

		    // Get some key info
		    $key_info = $gpg->keyinfo($info['fingerprint']);

		    // Get user
		    if ($user = getUserByKeyInfo($key_info)) {
			// Got a user, log them in!
			error_log("{$info['fingerprint']} matches user {$user->title}");

			system_message("Welcome {$user->title}!");

			login($user);
		    } else
			throw new \Exception("Fingerprint {$info['fingerprint']} does not match an known user!");
		} else
		    throw new \Exception("Problem verifying your signature: " . $gpg->geterror());
	    } else
		throw new \Exception("No profile link found in signature, aborting.");
	}
    } catch (\Exception $e) {
	// RegisterPages doesn't have a default exception handler, so lets do something with error messages
	register_error($e->getMessage());
    }
    
    // Register bookmark page handler
    elgg_register_page_handler('openpgpsingin', function($page) {

	if (isset($page[0])) {

	    elgg_load_library('openpgp-signin');
	    elgg_load_js('openpgpsignin');

	    switch ($page[0]) {
		
		case 'login' :
		    
		    $returnURL = getInput('u');
		
		    $user = elgg_get_logged_in_user_entity();
		
		    if (!$returnURL) throw new \Exception ('You need to send a return URL!');
		    if (!$user) throw new \Exception ('No user, this shouldn\'t happen');

		    // Ok, we have a user and a return URL, so lets encrypt and sign the url, and forward back passing the message back as the variable "key" with "u"
		    $gpg = new \gnupg();

		    if (!$gpg->addsignkey($user->pgp_privatekey_fingerprint, '')) throw new \Exception('There was a problem adding the signing key, have you set your keypair?','');

		    $signature = $gpg->sign($user->getUrl());
		    if (!$signature) throw new \Exception('There was a problem signing: ' . $gpg -> geterror());
		
		
		    // Render it and trigger a submit back
		    $body = elgg_view('openpgp-signin/login', ['signature' => $signature, 'user' => $user->getUrl(), 'return_url' => $returnURL]);
                    
		    echo elgg_view_page('Logging in...', elgg_view_layout('content', array(
			'content' => $body,
			'title' => 'Logging in...',
			'filter' => ''
		    )));
		    
		break;
	    }
	}

	return true;
    });
});
