<?php

/*
Plugin Name: Site Protect
Description: A Custom Plugin to Protect Site from unauthorized users. Only logined users are allowed to to see site.
Version: 1.0
Author: Jithin S
Text Domain: wp_site_protect
*/

global $wp_site_protect;
$wp_site_protect = new Wp_site_protect();
class Wp_site_protect
{

	/**
	 * Constructor
	 */
	public function __construct()
	{
		$this->errors = new WP_Error();
		register_activation_hook(__FILE__, array(&$this, 'install'));
		add_action('init', array($this, 'disable_caching'), 1);
		add_action('template_redirect', array($this, 'show_login_page_if_not_logged_in'), -1);
		add_action('init', array($this, 'process_login_request'), 1);
		add_action('dsl_error_messages', array($this, 'show_error_messages'));
	}
	/**
	 * Installation hook
	 */
	public function install(){
	}

	/**
	 * Disable Page Caching
	 */
	public function disable_caching()
	{
		if ($this->is_active() && !defined('DONOTCACHEPAGE')) {
			define('DONOTCACHEPAGE', true);
		}
	}


	/**
	 * Login URL
	 *
	 * @return  string  Login URL.
	 */
	public function login_url()
	{
		return add_query_arg('password-protected', 'login', home_url('/'));
	}

	/**
	 * Process Login Request
	 */
	public function process_login_request()
	{
		if ($this->is_active() && isset($_REQUEST['dsl_password'])) {
			$dsl_password = $_REQUEST['dsl_password'];
			$dsl_username = $_REQUEST['dsl_username'];

			# Credentials  DSL-1157
			$pwd = 'c0d517b74a67f5bef6353f1047a792e4';
			$uname = 'ACEResources2020';

			// If correct password...
			if ((hash_equals($pwd, md5($dsl_password)) && $pwd != '')  &&  $dsl_username == $uname) {

				$this->set_auth_cookie(false);
				$redirect_to = isset($_REQUEST['redirect_to']) ? $_REQUEST['redirect_to'] : '';
				$redirect_to = apply_filters('password_protected_login_redirect', $redirect_to);

				if (!empty($redirect_to)) {
					$this->safe_redirect(remove_query_arg('password-protected', $redirect_to));
					exit;
				} elseif (isset($_GET['dsl_password'])) {
					$this->safe_redirect(remove_query_arg('password-protected'));
					exit;
				}
			} else {

				// ... otherwise incorrect password
				$this->clear_auth_cookie();
				$this->errors->add('incorrect_password', __('Incorrect Username or Password', 'password-protected'));
			}
		}
	}


	/**
	 * Login Messages
	 * Outputs messages and errors in the login template.
	 */
	public function show_error_messages()
	{
		// Add message
		$message = apply_filters('dsl_error_message_filter', '');
		if (!empty($message)) {
			echo $message . "\n";
		}

		if ($this->errors->get_error_code()) {

			$errors = '';

			foreach ($this->errors->get_error_codes() as $code) {
				$severity = $this->errors->get_error_data($code);
				foreach ($this->errors->get_error_messages($code) as $error) {

					$errors .= $error . '<br />';
				}
			}

			if (!empty($errors)) {
				echo '<div id="login_error">' . apply_filters('dsl_error_message_filter', $errors) . "</div>\n";
			}
		}
	}

	/**
	 * Maybe Show Login
	 */
	public function show_login_page_if_not_logged_in()
	{

		// Filter for adding exceptions.
		$show_login = true;

		// Logged in
		if ($this->is_user_logged_in()) {
			$show_login = false;
		}

		if (!$show_login) {
			return;
		}

		// Show login form
		if (isset($_REQUEST['password-protected']) && 'login' == $_REQUEST['password-protected']) {

			$default_theme_file = locate_template(array('login-page.php'));

			if (empty($default_theme_file)) {
				$default_theme_file = dirname(__FILE__) . '/theme/login-page.php';
			}


			load_template($default_theme_file);
			exit();
		} else {

			$redirect_to = add_query_arg('password-protected', 'login', home_url());

			// URL to redirect back to after login
			$redirect_to_url = apply_filters('password_protected_login_redirect_url', (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI']);
			if (!empty($redirect_to_url)) {
				$redirect_to = add_query_arg('redirect_to', urlencode($redirect_to_url), $redirect_to);
			}

			nocache_headers();
			wp_redirect($redirect_to);
			exit();
		}
	}


	/**
	 * Parse Auth Cookie
	 *
	 * @param   string  $cookie  Cookie string.
	 * @param   string  $scheme  Cookie scheme.
	 * @return  string           Cookie string.
	 */
	public function parse_auth_cookie($cookie = '', $scheme = '')
	{

		if (empty($cookie)) {

			$cookie_name = $this->cookie_name();

			if (empty($_COOKIE[$cookie_name])) {
				return false;
			}

			$cookie = $_COOKIE[$cookie_name];
		}

		$cookie_elements = explode('|', $cookie);

		if (count($cookie_elements) != 3) {
			return false;
		}

		list($site_id, $expiration, $hmac) = $cookie_elements;

		return compact('site_id', 'expiration', 'hmac', 'scheme');
	}


	/**
	 * Validate Auth Cookie
	 *
	 * @param   string   $cookie  Cookie string.
	 * @param   string   $scheme  Cookie scheme.
	 * @return  boolean           Validation successful?
	 */
	public function validate_auth_cookie($cookie = '', $scheme = '')
	{

		if (!$cookie_elements = $this->parse_auth_cookie($cookie, $scheme)) {
			do_action('password_protected_auth_cookie_malformed', $cookie, $scheme);
			return false;
		}

		extract($cookie_elements, EXTR_OVERWRITE);

		$expired = $expiration;

		// Allow a grace period for POST and AJAX requests
		if (defined('DOING_AJAX') || 'POST' == $_SERVER['REQUEST_METHOD']) {
			$expired += 3600;
		}

		// Quick check to see if an honest cookie has expired
		if ($expired < current_time('timestamp')) {
			do_action('password_protected_auth_cookie_expired', $cookie_elements);
			return false;
		}

		$key = md5($this->get_site_id() . $this->get_hashed_password() . '|' . $expiration);
		$hash = hash_hmac('md5', $this->get_site_id() . '|' . $expiration, $key);

		if ($hmac != $hash) {
			do_action('password_protected_auth_cookie_bad_hash', $cookie_elements);
			return false;
		}

		if ($expiration < current_time('timestamp')) { // AJAX/POST grace period set above
			$GLOBALS['login_grace_period'] = 1;
		}

		return true;
	}

	/**
	 * Get Site ID
	 *
	 * @return  string  Site ID.
	 */
	public function get_site_id()
	{

		return 'dsl_ace_mentor_tools';
	}

	/**
	 * Is Active?
	 *
	 * @return  boolean  Is password protection active?
	 */
	public function is_active()
	{

		global $wp_query;

		// Always allow access to robots.txt
		if (isset($wp_query) && is_robots()) {
			return false;
		}

		$is_active = true;

		$is_active = apply_filters('dsl_is_active_password_protection', $is_active);

		if (isset($_GET['password-protected'])) {
			$is_active = true;
		}

		return $is_active;
	}

	/**
	 * Clear Authentication cookies
	 */
	public function clear_auth_cookie()
	{

		setcookie($this->cookie_name(), ' ', current_time('timestamp') - 31536000, COOKIEPATH, COOKIE_DOMAIN);
		setcookie($this->cookie_name(), ' ', current_time('timestamp') - 31536000, SITECOOKIEPATH, COOKIE_DOMAIN);
	}

	/**
	 * Cookie Name
	 *
	 * @return  string  Cookie name.
	 */
	public function cookie_name()
	{
		return 'wp_site_protection_cookie';
	}

	/**
	 * Generate Auth Cookie
	 *
	 * @param   int     $expiration  Expiration time in seconds.
	 * @param   string  $scheme      Cookie scheme.
	 * @return  string               Cookie.
	 */
	public function generate_auth_cookie($expiration, $scheme = 'auth')
	{

		$key = md5($this->get_site_id() . $this->get_hashed_password() . '|' . $expiration);
		$hash = hash_hmac('md5', $this->get_site_id() . '|' . $expiration, $key);
		$cookie = $this->get_site_id() . '|' . $expiration . '|' . $hash;

		return $cookie;
	}

	/**
	 * Set Auth Cookie
	 *
	 * @todo
	 *
	 * @param  boolean  $remember  Remember logged in.
	 * @param  string   $secure    Secure cookie.
	 */
	public function set_auth_cookie($remember = false, $secure = '')
	{

		if ($remember) {
			$expiration_time = 14 * DAY_IN_SECONDS * 20;
			$expiration = $expire = current_time('timestamp') + $expiration_time;
		} else {
			$expiration_time = DAY_IN_SECONDS * 20;
			$expiration = current_time('timestamp') + $expiration_time;
			$expire = 0;
		}

		if ('' === $secure) {
			$secure = is_ssl();
		}

		$secure_password_protected_cookie = apply_filters('password_protected_secure_password_protected_cookie', false, $secure);
		$password_protected_cookie = $this->generate_auth_cookie($expiration, 'password_protected');

		setcookie($this->cookie_name(), $password_protected_cookie, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_password_protected_cookie, true);
		if (COOKIEPATH != SITECOOKIEPATH) {
			setcookie($this->cookie_name(), $password_protected_cookie, $expire, SITECOOKIEPATH, COOKIE_DOMAIN, $secure_password_protected_cookie, true);
		}
	}

	/**
	 * Get Hashed Password
	 *
	 * @return  string  Hashed password.
	 */
	public function get_hashed_password()
	{

		return md5('dsl_auth_cookie' . wp_salt());
	}

	/**
	 * Logout
	 */
	public function logout()
	{

		$this->clear_auth_cookie();
		do_action('password_protected_logout');
	}

	/**
	 * Safe Redirect
	 *
	 * Ensure the redirect is to the same site or pluggable list of allowed domains.
	 * If invalid will redirect to ...
	 * Based on the WordPress wp_safe_redirect() function.
	 */
	public function safe_redirect($location, $status = 302)
	{

		$location = wp_sanitize_redirect($location);
		$location = wp_validate_redirect($location, home_url());

		wp_redirect($location, $status);
	}

	/**
	 * Maybe Process Logout
	 */
	public function maybe_process_logout()
	{

		if (isset($_REQUEST['password-protected']) && $_REQUEST['password-protected'] == 'logout') {

			$this->logout();

			if (isset($_REQUEST['redirect_to'])) {
				$redirect_to = remove_query_arg('password-protected', esc_url_raw($_REQUEST['redirect_to'], array('http', 'https')));
			} else {
				$redirect_to = home_url('/');
			}

			$this->safe_redirect($redirect_to);
			exit();
		}
	}

	/**
	 * Is User Logged In?
	 *
	 * @return  boolean
	 */
	public function is_user_logged_in()
	{

		return ($this->is_active() && $this->validate_auth_cookie()) || is_user_logged_in();
	}
}
