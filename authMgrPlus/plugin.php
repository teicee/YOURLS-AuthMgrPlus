<?php
/*
Plugin Name: Auth Manager Plus
Plugin URI:  https://github.com/joshp23/YOURLS-AuthMgrPlus
Description: Role Based Access Controlls with seperated user data for authenticated users
Version:     1.0.0
Author:      Josh Panter, nicwaller, Ian Barber <ian.barber@gmail.com>
Author URI:  https://unfettered.net
*/

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();

/****************** SET UP CONSTANTS ******************/

class AuthMgrPlusRoles { const Administrator = 'Administrator';
	const Editor        = 'Editor';
	const Contributor   = 'Contributor';
}

class AuthMgrPlusCapability {
	const ShowAdmin     = 'ShowAdmin';
	const AddURL        = 'AddURL';
	const DeleteURL     = 'DeleteURL';
	const EditURL       = 'EditURL';
	const ManageAnonURL = 'ManageAnonURL';
	const ManageUsrsURL = 'ManageUsrsURL';
	const ManagePlugins = 'ManagePlugins';
	const API           = 'API';
	const APIu          = 'APIu';
	const ViewStats     = 'ViewStats';
	const ViewAll       = 'ViewAll';
}	

/********** Add hooks to intercept functionality in CORE **********/

yourls_add_action( 'load_template_infos', 'authMgrPlus_intercept_stats' );
function authMgrPlus_intercept_stats() {
	if ( 'YOURLS_PRIVATE_INFOS' === true ) {
		authMgrPlus_require_capability( AuthMgrPlusCapability::ViewStats );
	}
}

yourls_add_action( 'api', 'authMgrPlus_intercept_api' );
function authMgrPlus_intercept_api() {
	if ( 'YOURLS_PRIVATE_API' === true ) {
		if ( isset( $_REQUEST['shorturl'] ) || isset( $_REQUEST['stats'] ) ) {
			authMgrPlus_require_capability( AuthMgrPlusCapability::APIu );
		} else {
			authMgrPlus_require_capability( AuthMgrPlusCapability::API );
		}
	}
}

yourls_add_action( 'auth_successful', 'authMgrPlus_intercept_admin' );
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
function authMgrPlus_intercept_admin() {
	authMgrPlus_require_capability( authMgrPlusCapability::ShowAdmin );

	// we use this GET param to send up a feedback notice to user
	if ( isset( $_GET['access'] ) && $_GET['access']=='denied' ) {
		yourls_add_notice('Access Denied');
	}

	$action_capability_map = array(
		'add' => AuthMgrPlusCapability::AddURL,
		'delete' => AuthMgrPlusCapability::DeleteURL,
		'edit_display' => AuthMgrPlusCapability::EditURL,
		'edit_save' => AuthMgrPlusCapability::EditURL,
		'activate' => AuthMgrPlusCapability::ManagePlugins,
		'deactivate' => AuthMgrPlusCapability::ManagePlugins,
	);
	// allow manipulation of this list ( be mindfull of extending Authmp Capability class if needed )
	yourls_apply_filter( 'authMgrPlus_action_capability_map', $action_capability_map);

	// Key actions like Add/Edit/Delete are AJAX requests
	if ( yourls_is_Ajax() ) {

		// Define some boundaries for ownership
		$restricted_actions = array( 'edit_display',
									'edit_save',
									'delete'
		);

		// Allow some flexability with those boundaries
		yourls_apply_filter( 'AuthMgrPlus_restricted_ajax_actions', $restricted_actions );

		$action_keyword = $_REQUEST['action'];
		$cap_needed = $action_capability_map[$action_keyword];

		// Check the action against those boundaries
		if ( in_array( $action_keyword, $restricted_actions) ) {
			$keyword = $_REQUEST['keyword'];
			$do = authMgrPlus_manage_keyword( $keyword, $cap_needed );
		} else {
			$do = authMgrPlus_have_capability( $cap_needed );
		}

		if ( $do !== true ) {
			$err = array();
			$err['status'] = 'fail';
			$err['code'] = 'error:authorization';
			$err['message'] = 'Access Denied';
			$err['errorCode'] = '403';
			echo json_encode( $err );
			die();
		}
	}

	// Intercept requests for plugin management
	if( isset( $_SERVER['REQUEST_URI'] ) && preg_match('/\/admin\/plugins\.php.*/', $_SERVER['REQUEST_URI'] ) ) {
		// Is this a plugin page request?
		if ( isset( $_REQUEST['page'] ) ) {
			// Is this an allowed plugin?
			global $authMgrPlus_allowed_plugin_pages;
			if ( authMgrPlus_have_capability( authMgrPlusCapability::ManagePlugins ) !== true) {
				$r = $_REQUEST['page'];
				if(!in_array($r, $authMgrPlus_allowed_plugin_pages ) ) {
					yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
				}
			}
		} else {
		// Should this user touch plugins?
			if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ManagePlugins ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}

		// intercept requests for global plugin management actions
		if (isset( $_REQUEST['plugin'] ) ) {
			$action_keyword = $_REQUEST['action'];
			$cap_needed = $action_capability_map[$action_keyword];
			if ( $cap_needed !== NULL && authMgrPlus_have_capability( $cap_needed ) !== true) {
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			}
		}
	}
}
/* 
 * Cosmetic filter: removes disallowed plugins from link list
*/
if( yourls_is_admin() ) {
	yourls_add_filter( 'admin_sublinks', 'authMgrPlus_admin_sublinks' );
}
function authMgrPlus_admin_sublinks( $links ) {
	
	global $authMgrPlus_allowed_plugin_pages;

	if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ManagePlugins ) !== true) {
		foreach( $links['plugins'] as $link => $ar ) {
			if(!in_array($link, $authMgrPlus_allowed_plugin_pages) )
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
yourls_add_filter( 'logout_link', 'authMgrPlus_html_append_roles' );
function authMgrPlus_html_append_roles( $original ) {
	$authenticated = yourls_is_valid_user();
	if ( $authenticated === true ) {
		$listcaps = implode(', ', authMgrPlus_current_capabilities());
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
function authMgrPlus_require_capability( $capability ) {
	if ( !authMgrPlus_have_capability( $capability ) ) {
		// If the user can't view admin interface, return a plain error.
		if ( !authMgrPlus_have_capability( AuthMgrPlusCapability::ShowAdmin ) ) {
		//	header("HTTP/1.0 403 Forbidden");
			die('Require permissions to show admin interface.');
		}
		// Otherwise, render errors in admin interface
		yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
		die();
	}
}

// Heart of system - Can the user do "X"?
function authMgrPlus_have_capability( $capability ) {

	global $authMgrPlus_anon_capabilities;
	global $authMgrPlus_role_capabilities;
	global $authMgrPlus_admin_ipranges;

	// Make sure the environment has been setup
	authMgrPlus_env_check();

	// Check anon capabilities
	$return = in_array( $capability, $authMgrPlus_anon_capabilities );

	// Check user-role based auth
	if( !$return ) {
		// Only users have roles.
		$authenticated = yourls_is_valid_user();
		if ( $authenticated !== true )
			return false;

		// List capabilities of particular user role
		$user_caps = array();
		foreach ( $authMgrPlus_role_capabilities as $rolename => $rolecaps ) {
				if ( authMgrPlus_user_has_role( YOURLS_USER, $rolename ) ) {
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
		foreach ($authMgrPlus_admin_ipranges as $range) {
			$return = authMgrPlus_cidr_match( $_SERVER['REMOTE_ADDR'], $range );
			if( $return ) 
				break;
		}
	}
	return $return;
}

// Determine whether a specific user has a role.
function authMgrPlus_user_has_role( $username, $rolename ) {

	global $authMgrPlus_role_assignment;

	// if no role assignments are created, grant everything FIXME: Make 'admin'
	// so the site still works even if stuff is configured wrong
	if ( empty( $authMgrPlus_role_assignment ) )
		return true;

	// do this the case-insensitive way
	// the entire array was made lowercase in environment check
	$username = strtolower($username);
	$rolename = strtolower($rolename);

	// if the role doesn't exist, give up now.
	if ( !in_array( $rolename, array_keys( $authMgrPlus_role_assignment ) ) )
		return false;

	$users_in_role = $authMgrPlus_role_assignment[$rolename];
	return in_array( $username, $users_in_role );	
}

/********************* KEYWORD OWNERSHIP ************************/

// Filter out restricted access to keyword data in...
// Admin list
yourls_add_filter( 'admin_list_where', 'authMgrPlus_admin_list_where' );
function authMgrPlus_admin_list_where($where) {

	if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ViewAll ) )
		return $where; // Allow admin/editor users to see the lot. 

	$user = YOURLS_USER;
	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$where['sql'] = $where['sql'] . " AND (`user` = :user OR `user` IS NULL) ";
		$where['binds']['user'] = $user;
	}
	else
		$where = $where . " AND (`user` = $user OR `user` IS NULL) ";

	return $where;
}
// API stats
yourls_add_filter( 'api_url_stats', 'authMgrPlus_api_url_stats' );
function authMgrPlus_api_url_stats( $return, $shorturl ) {
	$keyword = str_replace( YOURLS_SITE . '/' , '', $shorturl ); // accept either 'http://ozh.in/abc' or 'abc'
	$keyword = yourls_sanitize_string( $keyword );
	$keyword = addslashes($keyword);

	if(authMgrPlus_access_keyword($keyword))
		return $return;
	else
		return array('simple' => "URL is owned by another user", 'message' => 'URL is owned by another user', 'errorCode' => 403);
}
// Info pages
yourls_add_action( 'pre_yourls_infos', 'authMgrPlus_pre_yourls_infos' );
function authMgrPlus_pre_yourls_infos( $keyword ) {
	if( !authMgrPlus_access_keyword($keyword) ) {
		$authenticated = yourls_is_valid_user();
		if ( $authenticated === true ) 
				yourls_redirect( yourls_admin_url( '?access=denied' ), 302 );
			else
				yourls_redirect( YOURLS_SITE, 302 );
	}
}

// DB stats
yourls_add_filter( 'get_db_stats', 'authMgrPlus_get_db_stats' );
function authMgrPlus_get_db_stats( $return, $where ) {

	if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ViewAll ) )
		return $return; // Allow admin/editor users to see the lot. 

	// or... filter results
	global $ydb;
	$table_url = YOURLS_DB_TABLE_URL;
	$user = YOURLS_USER;
	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$where['sql'] = $where['sql'] . " AND (`user` = :user OR `user` IS NULL) ";
		$where['binds']['user'] = $user;
		$sql = "SELECT COUNT(keyword) as count, SUM(clicks) as sum FROM `$table_url` WHERE 1=1 " . $where['sql'];
		$binds = $where['binds'];
		$totals = $ydb->fetchObject($sql, $binds);
	} else {
		$where = $where . " AND (`user` = $user OR `user` IS NULL) ";
		$totals = $ydb->get_results("SELECT COUNT(keyword) as count, SUM(clicks) as sum FROM `$table_url` WHERE 1=1 " . $where );
	}
	$return = array( 'total_links' => $totals->count, 'total_clicks' => $totals->sum );

	return $return;
}

/********************* HOUSEKEEPING ************************/
// Validate environment setup
function authMgrPlus_env_check() {
	global $authMgrPlus_anon_capabilities;
	global $authMgrPlus_role_capabilities;
	global $authMgrPlus_role_assignment;
	global $authMgrPlus_admin_ipranges;
	global $authMgrPlus_allowed_plugin_pages;

	if ( !isset( $authMgrPlus_anon_capabilities) ) {
		$authMgrPlus_anon_capabilities = array();
	}

	if ( !isset( $authMgrPlus_role_capabilities) ) {
		$authMgrPlus_role_capabilities = array(
			AuthMgrPlusRoles::Administrator => array(
				AuthMgrPlusCapability::ShowAdmin,
				AuthMgrPlusCapability::AddURL,
				AuthMgrPlusCapability::EditURL,
				AuthMgrPlusCapability::DeleteURL,
				AuthMgrPlusCapability::ManageAnonURL,
				AuthMgrPlusCapability::ManageUsrsURL,
				AuthMgrPlusCapability::ManagePlugins,
				AuthMgrPlusCapability::API,
				AuthMgrPlusCapability::APIu,
				AuthMgrPlusCapability::ViewStats,
				AuthMgrPlusCapability::ViewAll,
			),
			AuthMgrPlusRoles::Editor => array(
				AuthMgrPlusCapability::ShowAdmin,
				AuthMgrPlusCapability::AddURL,
				AuthMgrPlusCapability::EditURL,
				AuthMgrPlusCapability::DeleteURL,
				AuthMgrPlusCapability::ManageAnonURL,
				AuthMgrPlusCapability::APIu,
				AuthMgrPlusCapability::ViewStats,
				AuthMgrPlusCapability::ViewAll,
			),
			AuthMgrPlusRoles::Contributor => array(
				AuthMgrPlusCapability::ShowAdmin,
				AuthMgrPlusCapability::AddURL,
				AuthMgrPlusCapability::EditURL,
				AuthMgrPlusCapability::DeleteURL,
				AuthMgrPlusCapability::APIu,
				AuthMgrPlusCapability::ViewStats,
			),
		);
	}

	if ( !isset( $authMgrPlus_role_assignment ) ) {
		$authMgrPlus_role_assignment = array();
	}

	if ( !isset( $authMgrPlus_admin_ipranges ) ) {
		$authMgrPlus_admin_ipranges = array(
			'127.0.0.0/8',
		);
	}

	if ( !isset( $authMgrPlus_allowed_plugin_pages ) ) {
		$authMgrPlus_allowed_plugin_pages = array(
		);
	}

	// convert role assignment table to lower case if it hasn't been done already
	// this makes searches much easier!
	$authMgrPlus_role_assignment_lower = array();
	foreach ( $authMgrPlus_role_assignment as $key => $value ) {
		$t_key = strtolower( $key );
		$t_value = array_map('strtolower', $value);
		$authMgrPlus_role_assignment_lower[$t_key] = $t_value;
	}
	$authMgrPlus_role_assignment = $authMgrPlus_role_assignment_lower;
	unset($authMgrPlus_role_assignment_lower);

	// allow manipulation of env by other plugins 
	// be mindfull of extending AuthMgrPlusCapability and AuthMgrPlusRoles classes if needed
	$a = $authMgrPlus_anon_capabilities;
	$b = $authMgrPlus_role_capabilities;
	$c = $authMgrPlus_role_assignment;
	$d = $authMgrPlus_admin_ipranges;
	$e = $authMgrPlus_allowed_plugin_pages;

	yourls_apply_filter( 'authMgrPlus_env_check', $a, $b, $c, $d, $e );

	return true;
}

// Activation: add the user column to the URL table if not added
yourls_add_action( 'activated_authMgrPlus/plugin.php', 'authMgrPlus_activated' );
function authMgrPlus_activated() {
	global $ydb; 
    
	$table = YOURLS_DB_TABLE_URL;
	$version = version_compare(YOURLS_VERSION, '1.7.3') >= 0;

	if ($version) {
		$sql = "DESCRIBE `$table`";
		$results = $ydb->fetchObjects($sql);
	} else {
		$results = $ydb->get_results("DESCRIBE $table");
	}

	$activated = false;
	foreach($results as $r) {
		if($r->Field == 'user') {
			$activated = true;
		}
	}
	if(!$activated) {
		if ($version) {
			$sql = "ALTER TABLE `$table` ADD `user` VARCHAR(255) NULL)";
			$insert = $ydb->fetchAffected($sql);
		} else {
			$ydb->query("ALTER TABLE `$table` ADD `user` VARCHAR(255) NULL");

		}
	}
}
/***************** HELPER FUNCTIONS ********************/

// List currently available capabilities
function authMgrPlus_current_capabilities() {
	$current_capabilities = array();
	$all_capabilities = array(
		AuthMgrPlusCapability::ShowAdmin,
		AuthMgrPlusCapability::AddURL,
		AuthMgrPlusCapability::EditURL,
		AuthMgrPlusCapability::DeleteURL,
		AuthMgrPlusCapability::ManageAnonURL,
		AuthMgrPlusCapability::ManageUsrsURL,
		AuthMgrPlusCapability::ManagePlugins,
		AuthMgrPlusCapability::API,
		AuthMgrPlusCapability::APIu,
		AuthMgrPlusCapability::ViewStats,
		AuthMgrPlusCapability::ViewAll,
	);
	// allow manipulation of this list ( be mindfull of extending the AuthMgrPlusCapability class if needed )
	yourls_apply_filter( 'authMgrPlus_current_capabilities', $all_capabilities);

	foreach ( $all_capabilities as $cap ) {
		if ( authMgrPlus_have_capability( $cap ) ) {
			$current_capabilities[] = $cap;
		}
	}

	return $current_capabilities;
}

// Check for IP in a range
// from: http://stackoverflow.com/questions/594112/matching-an-ip-to-a-cidr-mask-in-php5
function authMgrPlus_cidr_match($ip, $range) {
	list ($subnet, $bits) = explode('/', $range);
	$ip = ip2long($ip);
	$subnet = ip2long($subnet);
	$mask = -1 << (32 - $bits);
	$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
	return ($ip & $mask) == $subnet;
}

// Check user access to a keyword ( can they see it )
function authMgrPlus_access_keyword( $keyword ) {
	global $ydb; 

	if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ViewAll ) )
		return true;

	$table = YOURLS_DB_TABLE_URL;
	$user = null;
	if(defined('YOURLS_USER'))
		$user = YOURLS_USER;

	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$binds = array( 'keyword' => $keyword, 'user' => $user);
		$sql = "SELECT 1 FROM `$table` WHERE  (`user` IS NULL OR `user` = :user) AND `keyword` = :keyword";
		$result = $ydb->fetchAffected($sql, $binds);
	} else
		$result = $ydb->query("SELECT 1 FROM `$table` WHERE  (`user` IS NULL OR `user` = $user) AND `keyword` = $keyword");

	return $result > 0;
}
// Check user rights to a keyword ( can manage it )
function authMgrPlus_manage_keyword( $keyword, $capability ) {
	// only authenticated users can manaage keywords
	$authenticated = yourls_is_valid_user();
	if ( $authenticated !== true )
		return false;
	// Admin?
	if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ManageUsrsURL ) )
		return true;
	// Editor?
	$owner = authMgrPlus_keyword_owner();
	if ( $owner === null ) {
		if ( authMgrPlus_have_capability( AuthMgrPlusCapability::ManageAnonURL ) ) {
			return true;
		} else {
			return false;
		}
	}
	// Self Edit?
	$user = YOURLS_USER;
	if ( $owner === $user ) {
		if ( authMgrPlus_have_capability( $capability ) ) {
			return true;
		} else {
			return false;
		}
	}

	return false;
}
// Check keyword ownership
function authMgrPlus_keyword_owner( $keyword ) {
	global $ydb; 
	$table = YOURLS_DB_TABLE_URL;

	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$binds = array( 'keyword' => $keyword );
		$sql = "SELECT * FROM `$table` WHERE `keyword` = :keyword";
		$result = $ydb->fetchOne($sql, $binds);
	} else
		$result = $ydb->query("SELECT 1 FROM `$table` WHERE `keyword` = $keyword");

	return $result['user'];
}

// Record user info on keyword creation
yourls_add_action( 'insert_link', 'authMgrPlus_insert_link' );
function authMgrPlus_insert_link($actions) {
	global $ydb; 

	$keyword = $actions[2];
	$user = YOURLS_USER;
	$table = YOURLS_DB_TABLE_URL;

	// Insert $keyword against $username
	if (version_compare(YOURLS_VERSION, '1.7.3') >= 0) {
		$binds = array( 'user' => $user,
						'keyword' => $keyword);
		$sql = "UPDATE `$table` SET  `user` = :user WHERE `keyword` = :keyword";
		$result = $ydb->fetchAffected($sql, $binds);
	} else {
		$result = $ydb->query("UPDATE `$table` SET  `user` = $user WHERE `keyword` = $keyword");
	}
}
?>
