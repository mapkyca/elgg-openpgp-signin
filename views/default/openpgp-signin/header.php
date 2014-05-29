<?php
    if (elgg_get_context() == 'profile') {
	$url = elgg_get_site_url() . 'openpgpsignin/key/' . elgg_get_page_owner_entity()->username;
	
	header("Link: <{$url}>; rel=\"key\"", false);
	?>
<link href="<?= $url; ?>" rel="key" />	
	<?php
    }