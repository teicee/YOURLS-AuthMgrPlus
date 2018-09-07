<?php
/*
Plugin Name: Authorization Manager
Plugin URI:  https://github.com/nicwaller/yourls-authmgr-plugin
Description: Restrict classes of users to specific functions
Version:     0.11.0
Author:      nicwaller
Author URI:  https://github.com/nicwaller
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/****************** SET UP CONSTANTS ******************/

class AuthmgrRoles {
	const Administrator = 'Administrator';
	const Editor        = 'Editor';
	const Contributor   = 'Contributor';
}

class AuthmgrCapability {
	const ShowAdmin     = 'ShowAdmin';
	const AddURL        = 'AddURL';
	const DeleteURL     = 'DeleteURL';
	const EditURL       = 'EditURL';
	const ManagePlugins = 'ManagePlugins';
	const API           = 'API';
	const APIu          = 'APIu';
	const ViewStats     = 'ViewStats';
}	

/********** Add hooks to intercept functionality in CORE **********/

yourls_add_action( 'load_template_infos', 'authmgr_intercept_stats' );
function authmgr_intercept_stats() {
	if ( 'YOURLS_PRIVATE_INFOS' === true ) {
		authmgr_require_capability( AuthmgrCapability::ViewStats );
	}
}

yourls_add_action( 'api', 'authmgr_intercept_api' );
function authmgr_intercept_api() {
	if ( 'YOURLS_PRIVATE_API' === true ) {
		if ( isset( $_REQUEST['shorturl'] ) ) {		
			authmgr_require_capability( AuthmgrCapability::APIu );
		} else {
			authmgr_require_capability( AuthmgrCapability::API );
		}
	}
}


yourls_add_action( 'auth_successful', 'authmgr_intercept_admin' );
/**
 * YOURLS processes most actions in the admin page. It would be ideal
 * to add a unique hook for each action, but unfortunately we need to
 * hook the admin page load itself, and try to figure out what action
 * is intended.
 *
 * TODO: look for these hooks
 *
 * At this point, reasonably assume that the current request is for
 * a rendering of the admin page.
 */
function authmgr_intercept_admin() {
	authmgr_require_capability( AuthmgrCapability::ShowAdmin );

	// we use this GET param to send up a feedback notice to user
	if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
		yourls_add_notice('Access Denied');
	}

	$action_capability_map = array(
		'add' => AuthmgrCapability::AddURL,
		'delete' => AuthmgrCapability::DeleteURL,
		'edit_display' => AuthmgrCapability::EditURL,
		'edit_save' => AuthmgrCapability::EditURL,
		'activate' => AuthmgrCapability::ManagePlugins,
		'deactivate' => AuthmgrCapability::ManagePlugins,
	);
	// allow manipulation of this list ( be mindfull of extending Authmgr Capability class if needed )
	yourls_apply_filter( 'authmgr_action_capability_map', $action_capability_map);

	// Intercept requests for plugin management
	if( isset( $_SERVER['REQUEST_URI'] ) && preg_match('/\/admin\/plugins\.php.*/', $_SERVER['REQUEST_URI'] ) ) {
		// Is this a plugin page request?
		if ( isset( $_REQUEST['page'] ) ) {
			// Is this an allowed plugin?
			global $authmgr_allowed_plugin_pages;
			if ( authmgr_have_capability( AuthmgrCapability::ManagePlugins ) !== true) {
				$r = $_REQUEST['page'];
				if(!in_array($r, $authmgr_allowed_plugin_pages ) ) {
					yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
				}
			}
		} else {
		// Should this user touch plugins?
			if ( authmgr_have_capability( AuthmgrCapability::ManagePlugins ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}

		// intercept requests for global plugin management actions
		if (isset( $_REQUEST['plugin'] ) ) {
			$action_keyword = $_REQUEST['action'];
			$cap_needed = $action_capability_map[$action_keyword];
			if ( $cap_needed !== NULL && authmgr_have_capability( $cap_needed ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}
	}

	// Key actions like Add/Edit/Delete are AJAX requests
	if ( yourls_is_Ajax() ) {
		$action_keyword = $_REQUEST['action'];
		$cap_needed = $action_capability_map[$action_keyword];
		if ( authmgr_have_capability( $cap_needed ) !== true) {
			$err = array();
			$err['status'] = 'fail';
			$err['code'] = 'error:authorization';
			$err['message'] = 'Access Denied';
			$err['errorCode'] = '403';
			echo json_encode( $err );
			die();
		}
	}
}
/* 
 * Cosmetic filter: removes disallowed plugins from link list
*/
yourls_add_filter( 'admin_sublinks', 'authmgr_admin_sublinks' );
function authmgr_admin_sublinks( $links ) {
	
	global $authmgr_allowed_plugin_pages;

	if ( authmgr_have_capability( AuthmgrCapability::ManagePlugins ) !== true) {
		foreach( $links['plugins'] as $link => $ar ) {
			if(!in_array($link, $authmgr_allowed_plugin_pages) )
				unset($links['plugins'][$link]);
		}
	}
	sort($links['plugins']);
	return $links;
}

/*
 * Cosmetic filter: displays currently available roles
 * by hovering mouse over the username in logout link.
 */
yourls_add_filter( 'logout_link', 'authmgr_html_append_roles' );
function authmgr_html_append_roles( $original ) {
	$authenticated = yourls_is_valid_user();
	if ( $authenticated === true ) {
		$listcaps = implode(', ', authmgr_current_capabilities());
		return '<div title="'.$listcaps.'">'.$original.'</div>';
	} else {
		return $original;
	}
}

/**************** CAPABILITY TESTING ****************/

/*
 * If capability is not permitted in current context, then abort.
 * This is the most basic way to intercept unauthorized usage.
 */
// TODO: API responses!
function authmgr_require_capability( $capability ) {
	if ( !authmgr_have_capability( $capability ) ) {
		// If the user can't view admin interface, return a plain error.
		if ( !authmgr_have_capability( AuthmgrCapability::ShowAdmin ) ) {
			header("HTTP/1.0 403 Forbidden");
			die('Require permissions to show admin interface.');
		}
		// Otherwise, render errors in admin interface
		yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		die();
	}
}

// Heart of system
function authmgr_have_capability( $capability ) {

	global $authmgr_anon_capabilities;
	global $authmgr_role_capabilities;
	global $authmgr_admin_ipranges;

	// Make sure the environment has been setup
	authmgr_env_check();

	// Check anon capabilities
	$return = in_array( $capability, $authmgr_anon_capabilities );

	// Check user-role based auth
	if( !$return ) {
		// Only users have roles.
		$authenticated = yourls_is_valid_user();
		if ( $authenticated !== true )
			return false;

		// List capabilities of particular user role
		$user_caps = array();
		foreach ( $authmgr_role_capabilities as $rolename => $rolecaps ) {
				if ( authmgr_user_has_role( YOURLS_USER, $rolename ) ) {
						$user_caps = array_merge( $user_caps, $rolecaps );
				}
		}
		$user_caps = array_unique( $user_caps );
		// Is the requested capability in this list?
		$return =  in_array( $capability, $user_caps );
	}

	// Is user connecting from an admin designated IP?
	if( !$return ) {
		// the array of ranges: '127.0.0.0/8' will always be admin
		foreach ($authmgr_admin_ipranges as $range) {
			$return = authmgr_cidr_match( $_SERVER['REMOTE_ADDR'], $range );
			if( $return ) 
				break;
		}
	}

	return $return;
}

// Determine whether a specific user has a role.
function authmgr_user_has_role( $username, $rolename ) {

	global $authmgr_role_assignment;

	// if no role assignments are created, grant everything FIXME: Make 'admin'
	// so the site still works even if stuff is configured wrong
	if ( empty( $authmgr_role_assignment ) )
		return true;

	// do this the case-insensitive way
	// the entire array was made lowercase in environment check
	$username = strtolower($username);
	$rolename = strtolower($rolename);

	// if the role doesn't exist, give up now.
	if ( !in_array( $rolename, array_keys( $authmgr_role_assignment ) ) )
		return false;

	$users_in_role = $authmgr_role_assignment[$rolename];
	return in_array( $username, $users_in_role );	
}

/********************* VALIDATE CONFIGURATION ************************/

function authmgr_env_check() {
	global $authmgr_anon_capabilities;
	global $authmgr_role_capabilities;
	global $authmgr_role_assignment;
	global $authmgr_admin_ipranges;
	global $authmgr_allowed_plugin_pages;

	if ( !isset( $authmgr_anon_capabilities) ) {
		$authmgr_anon_capabilities = array();
	}

	if ( !isset( $authmgr_role_capabilities) ) {
		$authmgr_role_capabilities = array(
			AuthmgrRoles::Administrator => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::DeleteURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::ManagePlugins,
				AuthmgrCapability::API,
				AuthmgrCapability::APIu,
				AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Editor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::EditURL,
				AuthmgrCapability::DeleteURL,
				AuthmgrCapability::APIu,
				AuthmgrCapability::ViewStats,
			),
			AuthmgrRoles::Contributor => array(
				AuthmgrCapability::ShowAdmin,
				AuthmgrCapability::AddURL,
				AuthmgrCapability::APIu,
				AuthmgrCapability::ViewStats,
			),
		);
	}

	if ( !isset( $authmgr_role_assignment ) ) {
		$authmgr_role_assignment = array();
	}

	if ( !isset( $authmgr_admin_ipranges ) ) {
		$authmgr_admin_ipranges = array(
			'127.0.0.0/8',
		);
	}

	if ( !isset( $authmgr_allowed_plugin_pages ) ) {
		$authmgr_allowed_plugin_pages = array(
		);
	}

	// convert role assignment table to lower case if it hasn't been done already
	// this makes searches much easier!
	$authmgr_role_assignment_lower = array();
	foreach ( $authmgr_role_assignment as $key => $value ) {
		$t_key = strtolower( $key );
		$t_value = array_map('strtolower', $value);
		$authmgr_role_assignment_lower[$t_key] = $t_value;
	}
	$authmgr_role_assignment = $authmgr_role_assignment_lower;
	unset($authmgr_role_assignment_lower);

	// allow manipulation of env by other plugins 
	// be mindfull of extending AuthmgrCapability and AuthmgrRoles classes if needed
	$a = $authmgr_anon_capabilities;
	$b = $authmgr_role_capabilities;
	$c = $authmgr_role_assignment;
	$d = $authmgr_admin_ipranges;
	$e = $authmgr_allowed_plugin_pages;

	yourls_apply_filter( 'authmgr_env_check', $a, $b, $c, $d, $e );

	return true;
}

/***************** HELPER FUNCTIONS ********************/

// List currently available capabilities
function authmgr_current_capabilities() {
	$current_capabilities = array();
	$all_capabilities = array(
		AuthmgrCapability::ShowAdmin,
		AuthmgrCapability::AddURL,
		AuthmgrCapability::DeleteURL,
		AuthmgrCapability::EditURL,
		AuthmgrCapability::ManagePlugins,
		AuthmgrCapability::API,
		AuthmgrCapability::APIu,
		AuthmgrCapability::ViewStats,
	);
	// allow manipulation of this list ( be mindfull of extending the AuthmgrCapability class if needed )
	yourls_apply_filter( 'authmgr_current_capabilities', $all_capabilities);

	foreach ( $all_capabilities as $cap ) {
		if ( authmgr_have_capability( $cap ) ) {
			$current_capabilities[] = $cap;
		}
	}

	return $current_capabilities;
}

// Check for IP in a range
// from: http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
function authmgr_cidr_match($ip, $range) {
	list ($subnet, $bits) = explode('/', $range);
	$ip = ip2long($ip);
	$subnet = ip2long($subnet);
	$mask = -1 << (32 - $bits);
	$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
	return ($ip & $mask) == $subnet;
}
