<?php

/**
 * Get a fingerprint for a key, returning an array of keys and subkeys
 * @param type $key_info
 * @param array $fingerprints
 */
function getFingerprintsFromKeyinfo($key_info, array &$fingerprints) {
    foreach ($key_info as $info) {
	// Fingerprint found, so add it
	if (isset($info['fingerprint'])) {
	    $fingerprints[] = $info['fingerprint'];
	}
	// If there are subkeys
	if (isset($info['subkeys']))
	    getFingerprintsFromKeyinfo($info['subkeys'], $fingerprints);
    }
}

/**
 * Retrieve a user associated with a PGP key fingerprint.
 * @return \Idno\Entities\User
 */
function getUserByKeyInfo(array $key_info) {
    $fingerprints = [];
    getFingerprintsFromKeyinfo($key_info, $fingerprints); // Find fingerprints from keys and subkeys

    foreach ($fingerprints as $fingerprint) {
	error_log("Looking for users identified with $fingerprint");

	if ($result = elgg_get_entities_from_metadata([
	    'type' => 'user',
	    'name' => 'pgp_publickey_fingerprint',
	    'value' => $fingerprint,
	    'limit' => 1
		])) {
	    foreach ($result as $row) {
		return $row;
	    }
	}
    }

    return false;
}

/**
 * When given a profile page, it will attempt to find the appropriate public key data.
 * 
 * First it'll look for a <link href="......" rel="key"> in the header, or a Link: <url>; rel="key" in the header.
 * Failing that it'll look for a class="key" block on the page.
 * 
 * @param type $url
 * @return string|false Will return the new key's fingerprint or FALSE
 */
function findPublicKey($url) {

    if ($page = file_get_contents($url)) {

	$endpoint_url = null;


	// Get headers from request
	$headers = $http_response_header;


	// See if we have an endpoint in header
	foreach ($headers as $header) {
	    if ((preg_match('~<(https?://[^>]+)>; rel="key"~', $header, $match)) && (!$endpoint_url)) {
		$endpoint_url = $match[1];
		error_log("Found endpoint URL <{$endpoint_url}> in HTTP header");
	    }
	}

	// Nope, so see if we have it in meta
	if (!$endpoint_url) {
	    if (preg_match('/<link href="([^"]+)" rel="key" ?\/?>/i', $page, $match)) {
		$endpoint_url = $match[1];
		error_log("Found endpoint URL <{$endpoint_url}> in meta");
	    }
	}

	// Still nope, see if we've linked to it in page
	if (!$endpoint_url) {
	    if (preg_match('/<a href="([^"]+)" rel="key" ?\/?>/i', $page, $match)) {
		$endpoint_url = $match[1];
		error_log("Found endpoint URL <{$endpoint_url}> in a link on the page");
	    }
	}
	if (!$endpoint_url) {
	    if (preg_match('/<a rel="key" href="([^"]+)" ?\/?>/i', $page, $match)) {
		$endpoint_url = $match[1];
		error_log("Found endpoint URL <{$endpoint_url}> in a link on the page");
	    }
	}

	$key = null;
	if ($endpoint_url) {
	    // Yes, we have an endpoint URL, go get the key data
	    error_log("Retrieving key data...");
	    $key = trim(file_get_contents($endpoint_url));
	}

	// If no key data, try and find key data within a classed block on the page
	if (!$key) {
	    if (preg_match('/<[^\s]+ class="[^"]*key[^"]*">([^<]*)/im', $page, $match)) {
		error_log("Still no key data, looking on the page...");
		$key = $match[1];
	    }
	}

	// We have some key data, try and use it!
	if ($key) {
	    error_log("Some key data was found... $key");
	    return $key;
	}


	error_log("No key data found :(");
    } else
	error_log("Could not load $url");

    return false;
}

/**
 * Return whether the uuid is a local address.
 */
function is_local_url($uuid) {
    if (($uuid_parse = parse_url($uuid)) && ($url_parse = parse_url(elgg_get_site_url()))) {
	if ($uuid_parse['host'] == $url_parse['host']) {
	    return true;
	}
    }

    return false;
}

/**
 * Retrieve the cleartext from a clear signature
 * @param type $signature
 * @return boolean
 */
function getCleartextFromSig($signature) {

	if (preg_match_all("/Hash:\ [^\s]+\n\n((.*)+)/s", $signature, $matches, PREG_SET_ORDER))
	{ 
		$sig = $matches[0][1];
		return substr($sig, 0 , strpos($sig, '-----BEGIN'));
	}
	return false;
}