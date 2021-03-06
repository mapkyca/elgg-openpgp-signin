<?php

/**
 * OpenPGP Signin.
 * 
 * Open PGP signin support for Elgg (based on the one I wrote for Idno)
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

    // Extend header
    elgg_extend_view('page/elements/head', 'openpgp-signin/header');
    
    // Provide my own user save
    elgg_register_action('elgg-openpgp-signin/usersettings/save', dirname(__FILE__) . '/actions/usersettings/save.php');

    // Register friend
    elgg_register_event_handler('create', 'friend', function ($event, $type, $object) {

	if ($user_two = get_entity($object->guid_two)) {
	    
	    elgg_load_library('openpgp-signin');
	    
	    if ($publickey = findPublicKey($user_two->getUrl())) {
		
		// Save it to the keyring
		$gpg = new \gnupg();
		$result = $gpg->import($publickey);

		// Save a signature against the user
		if ($result && isset($result['fingerprint'])) {
		    error_log("Imported public key, with fingerprint {$result['fingerprint']}");

		    // Save against following user

		    $user_two->pgp_publickey_fingerprint = $result['fingerprint'];
		} else {
		    error_log("Key data could not be imported");
		}
	    }
	    
	}
	
    });

    // Signature specified on any page, grab it and save it
    if (isset($_REQUEST['signature'])) {
	error_log("Ooo... we have a signature, saving in session for later...");
	$_SESSION['_PGP_SIGNATURE'] = $_REQUEST['signature'];
	error_log("Signature is: {$_SESSION['_PGP_SIGNATURE']}");
    }

    try {

	elgg_load_library('openpgp-signin');
	
	// Log user in based on their signature (if there is no logged in user, and signature present in session
	if (isset($_SESSION['_PGP_SIGNATURE']) && (!elgg_get_logged_in_user_entity())) {

	    $signature = $_SESSION['_PGP_SIGNATURE'];

	    $user_id = null;
	    $request_url = null;
	    if (preg_match_all("/(https?:\/\/[^\s]+)/", $signature, $matches, PREG_SET_ORDER)) {
		$user_id = $matches[0][0];
		$request_url = $matches[1][0]; 
	    }
	    
	    // Check that this is not sent to the wrong site
	    if (!$request_url) throw new \Exception ("Request URL missing from signature");
	    if (!is_local_url($request_url)) throw new \Exception ("Sorry, you're requesting a URL which does not belong to this site!");
	    
	    // Now, we check the timestamp to check for Replay attacks
	    $now = time();
	    if (preg_match('/([0-9]{4}-?[0-9]{2}-?[0-9]{2}T[0-9]{2}:?[0-9]{2}:?[0-9]{2}[+-Z]?([0-9]{2,4}:?([0-9]{2})?)?)/',$signature, $matches))
		$timestamp = strtotime($matches[0]);

	    if (!$timestamp) throw new \Exception("No timestamp was found in signature! Make sure you include a timestamp in ISO8601 format");
	    if (($timestamp < $now - 5) || ($timestamp > $now + 5)) // 5 seconds grace either way
		throw new \Exception ("Sorry, you could not be logged in because the timestamp was wrong. Check your computer's clock is correct, and ideally connect to an internet time server!");

	    if ($user_id) {

		$gpg = new \gnupg();

		//$signature = substr($signature, strpos($signature, '-----BEGIN PGP SIGNATURE-----')); // GPG verify won't take the full sig, so only return the appropriate bit

		if ($info = $gpg->verify($signature, false/*, getCleartextFromSig($signature)*/)) {

		    if (isset($info[0]))
			$info = $info[0]; 

		    if ($info['summary']==4)
			throw new \Exception('Sorry, the signature appears to be invalid'); // Not sure, but I think summary of 4 is an invalid signature, no docs, but seems to be from observation
		    
		    error_log("Signature verified as : " . print_r($info, true));

		    // Get some key info
		    $key_info = $gpg->keyinfo($info['fingerprint']);

		    // Get user
		    if ($user = getUserByKeyInfo($key_info)) {
			
			// Check nonce, make sure this isn't a replay
			$nonce = md5($user_id.$request_url.$timestamp);
			
			// Pull nonces from user or create
			$nonces = unserialize($user->ops_nonces);
			if ((!$nonces) || (!is_array($nonces)))
			    $nonces = [];
			
			// Check nonce in list, exception if exist
			if (isset($nonces[$nonce])) throw new \Exception('Sorry, I\'ve seen this login before. Refresh your page, clear your caches, chant three times and try again...');
			
			// Add nonce to list, sort by timestamp, then delete old ones (5 mins)
			$nonces[$nonce] = $timestamp;
			
			// Remove old nonces
			$cutoff = time()-300; // 5minutes
			$tmp_n = [];
			foreach ($nonces as $n => $t) {
			    if ($t > $cutoff)
				$tmp_n[$n] = $t;
			}
			$nonces = $tmp_n;
			    
			$user->ops_nonces = serialize($nonces); 
			$user->save();
			
			
			// Got a user, log them in!
			error_log("{$info['fingerprint']} matches user {$user->name}");

			system_message("Welcome {$user->name}!");

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
    elgg_register_page_handler('openpgpsignin', function($page) {

	if (isset($page[0])) {

	    elgg_load_library('openpgp-signin');
	    elgg_load_js('openpgpsignin');

	    switch ($page[0]) {

		case 'login' :

		    $returnURL = get_input('u');
		    
		    gatekeeper();

		    $user = elgg_get_logged_in_user_entity();

		    if (!$returnURL)
			throw new \Exception('You need to send a return URL!');
		    if (!$user)
			throw new \Exception('No user, this shouldn\'t happen');

		    // Ok, we have a user and a return URL, so lets encrypt and sign the url, and forward back passing the message back as the variable "key" with "u"
		    $gpg = new \gnupg();

		    if (!$gpg->addsignkey($user->pgp_privatekey_fingerprint, ''))
			throw new \Exception('There was a problem adding the signing key, have you set your keypair? '. $gpg->geterror());

		    $signature = $gpg->sign(date('c', time()) . " \n" .$user->getUrl() . " \n" . $returnURL);
		    if (!$signature)
			throw new \Exception('There was a problem signing: ' . $gpg->geterror());


		    // Render it and trigger a submit back
		    $body = elgg_view('openpgp-signin/login', ['signature' => $signature, 'user' => $user->getUrl(), 'return_url' => $returnURL]);

		    echo elgg_view_page('Logging in...', elgg_view_layout('content', array(
			'content' => $body,
			'title' => 'Logging in...',
			'filter' => ''
		    )));

		    break;

		case 'key' :
		    set_input('username', $page[1]);

		    $user = get_user_by_username($page[1]);
		    if ($user) {
			if ($key = elgg_get_plugin_user_setting('public_key', $user->guid, 'elgg-openpgp-signin')) {
			    header('Content-Type: text/plain');

			    echo $key;
			    exit;
			}
		    }

		    echo "No key for {$page[1]}";
		    http_response_code(404);

		    exit;
		    break;
	    }
	}

	return true;
    });
});
