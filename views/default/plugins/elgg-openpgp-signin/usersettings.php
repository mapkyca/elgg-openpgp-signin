<?php
$user = elgg_get_logged_in_user_entity();

	    elgg_load_js('openpgpsignin');
	    
$public_key = elgg_get_plugin_user_setting('public_key', $user->guid, 'elgg-openpgp-signin');
$private_key = elgg_get_plugin_user_setting('private_key', $user->guid, 'elgg-openpgp-signin');

?>
<?php
if (($public_key) && ($private_key)) {
    ?>
    <div class="row">
        <div class="span9 offset1  well">
    	<p>Now you've saved your keys, you can sign in to other sites (that use this plugin) using your public key. Use this bookmarklet to make this process easier.</p>

    	<div class="bookmarklet"><?= elgg_view('openpgp-signin/bookmarklet'); ?></div>
        </div>

    </div>
    <?php
}
?>
<div class="row">
    <div class="span10 offset1">
	    <input type="hidden" id="pgp-keys-userid" value="<?= $user->username; ?>@<?= parse_url(elgg_get_site_url(), PHP_URL_HOST); ?>" />

            <div class="control-group">
                <div class="controls">
                    <p>
                        Paste the ASCII armored version of you PGP key in the boxes below, or save a blank box to generate a new keypair on the server.
                    </p>
                    <div class="control-group">
                        <label class="control-label" for="user_token">Public Key</label>
                        <div class="controls">
                            <textarea id="public_key" name="params[public_key]" class="span4"><?= htmlspecialchars($public_key) ?></textarea>
                        </div>
                    </div>

                    <div class="control-group">
                        <label class="control-label" for="app_token">Private Key</label>
                        <div class="controls">
                            <textarea id="private_key" name="params[private_key]" class="span4"><?= htmlspecialchars($private_key) ?></textarea>
                        </div>
                    </div>

                    <div class="control-group">
                        <div class="controls">
                            <a href="#" id="generate" class="btn btn-danger">Generate...</a> 
                        </div>
                    </div>
                </div>
            </div>  
    </div>
</div>

<script>
    $(document).ready(function() {

	$('#generate').click(function(event) {
	    var openpgp = window.openpgp;

	    $(this).text('Generating...');

	    key = openpgp.generateKeyPair(1, 2048, $('#pgp-keys-userid').val(), '');

	    $('#public_key').val(key.publicKeyArmored);
	    $('#private_key').val(key.privateKeyArmored);


	    if (($('#public_key').val() != "") && ($('#private_key').val() != "")) {
		$(this).fadeOut();
	    }
	});

    });
</script>