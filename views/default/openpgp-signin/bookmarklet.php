<?php

$user = elgg_get_logged_in_user_entity();

?><a href="javascript:(function(){location.href='<?= elgg_get_site_url(); ?>openpgpsignin/login?u='+encodeURIComponent(location.href);})();">Sign in as <?= $user->name; ?>...</a>