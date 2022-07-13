<?php
global $wp_version, $dsl_site_protect, $is_iphone;
nocache_headers();
header( 'Content-Type: ' . get_bloginfo( 'html_type' ) . '; charset=' . get_bloginfo( 'charset' ) )
?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" <?php language_attributes(); ?>>
<head>

<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php bloginfo( 'charset' ); ?>" />
<title><?php get_bloginfo( 'name' ); ?></title>
<?php

if ( version_compare( $wp_version, '3.9-dev', '>=' ) ) {
	wp_admin_css( 'login', true );
} else {
	wp_admin_css( 'wp-admin', true );
	wp_admin_css( 'colors-fresh', true );
}

?>

<style media="screen">
#login_error, .login .message, #loginform { 
	margin-bottom: 20px; padding: 40px 120px;
	}
body.login div#login h1 a {
		background-image: url('https://161.47.95.136/assets/img/ACE-Mentor-Program0A.png'); 
	}
	body.login p {
		text-align: center;
	}	
	.login-password-protected #login	{
		width: 640px;
	}
	p label {
		float: left;
	}
</style>
<?php

if ( $is_iphone ) {
	?>
	<meta name="viewport" content="width=320; initial-scale=0.9; maximum-scale=1.0; user-scalable=0;" />
	<style media="screen">
	.login form, .login .message, #login_error { margin-left: 0px; }
	.login #nav, .login #backtoblog { margin-left: 8px; }
	.login h1 a { width: auto; }
	#login { padding: 20px 0; }
	</style>
	<?php
}

?>
</head>
<body class="login login-password-protected login-action-password-protected-login wp-core-ui">

<div id="login">
<h1><a href="<?php echo esc_url( home_url( '/' )); ?>" title="<?php echo esc_attr(get_bloginfo( 'name' ) ); ?>"><?php bloginfo( 'name' ); ?></a></h1>

<div class='login-message'>
<p>The ACE Mentor Tools site is restricted to current ACE participants. You must have a complete ACE registration for the current program year - or be provided login credentials by a program leader - to be permitted access to this site.</p>
<br/>
<p>Please <a href='https://app.acementor.org/login'>log in to your ACE profile</a> and go to the resources section for more information.</p>
<br/>
<p>If you do not have an ACE profile but need access to this site, please contact an affiliate leader.</p>
<br/>
<p>If all above efforts are unsuccessful, please email us: <a href='mailto:info@acementor.org'>info@acementor.org</a></p>
</div>

<form name="loginform" id="loginform" action="<?php echo esc_url( $dsl_site_protect->login_url() ); ?>" method="post">
<?php do_action( 'dsl_error_messages' ); ?>

<p>
				<label for="dsl_username">Username</label>
				<input type="text" name="dsl_username" id="dsl_username" aria-describedby="login_error" class="input" value="" size="20" autocapitalize="off">
			</p>
			<div class="user-pass-wrap">
				<label for="user_pass">Password</label>
				<div class="wp-pwd">
					<input type="password" name="dsl_password" id="dsl_password" aria-describedby="login_error" class="input password-input" value="" size="20">
					<button type="button" class="button button-secondary wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Show password">
						<span class="dashicons dashicons-visibility" aria-hidden="true"></span>
					</button>
				</div>
			</div>
        <p class="submit">
			<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Log In' ); ?>" tabindex="100" />
			<input type="hidden" name="password_protected_cookie_test" value="1" />
			<input type="hidden" name="password-protected" value="login" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( ! empty( $_REQUEST['redirect_to'] ) ? $_REQUEST['redirect_to'] : '' ); ?>" />
		</p>
    </form>
    </div>
</body>