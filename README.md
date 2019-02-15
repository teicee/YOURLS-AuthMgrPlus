YOURLS-AuthMgrPlus
=====================

This plugin manages essential YOURLS funtions and seperates user data with role-based access controls (RBAC). With access controls enabled, you can safely delegate access to the admin pages and API while keeping link data private. You share an installation, log on, add a link, and nobody else sees it.

Features
--------
-  Easily assign users to roles
-  Easily fine tune role permissions
-  IP based Authentication (optional)
-  All plugin pages, including main management page, hidden to non-admins by default. Easy to unblock pages.
-  Plenty of hooks to filter Roles, Role Capabilities, and _any_ of the default data environemnt (such as plugin page visibility)
-  Fine(r) tuned API access
-  PHP 7 compatible

Requirements
------------
- YOURLS 1.7.2 (1.7.3 ready).
- If they are isntalled, uninstall nicwaller's `authmgr` and/or Ian Barber's `Seperate Users` plugins.

Installation
------------
1. Download the [latest release](https://github.com/joshp23/YOURLS-AuthMgrPlus) of ythis plugin.
1. Copy the `authMgrPlus` folder into your `user/plugins` folder for YOURLS.
1. Set up some parameters for authMgrPlus (details below)
1. Activate the plugin with the plugin manager in the YOURLS admin interface.

Default Roles
-------------
The default roles are set up as follows:

Role          | Capabilities
--------------|---------------------------------------------------------------------------------------------------
Administrator | Can manage plugins, no limits
Editor        | Can add (+API), access own and all others', edit & delete own & anon URL's
Contributor   | Can add (+API), access own and anon's, and edit & delete own URLs
Anonymous     | Can add and access (see stats, etc) anon links (If public)

Configuration
-------------
Add role assignments to your `user/config.php` file.

```
$authMgrPlus_role_assignment = array(
  'administrator' => array(
    'your_username',
  ),
  'editor' => array(
    'your_close_friend',
  ),
  'contributor' => array(
    'your_other_friend',
  ),
);
```

You can also designate a range of IP addresses that will automatically be granted all capabilities. By default, all accesses from IPv4 localhost (127.0.0.0/8) are granted full access.

```
$authMgrPlus_admin_ipranges = array(
    '127.0.0.0/8',
);
```
Plugin management and plugin pages are available to admins only by default. Individual pages can be exposed to non-admin roles like so:
```
$authMgrPlus_allowed_plugin_pages = array(
	'sample_page',
	'another_plugin_slug'
);
```
Explore the code to see how to set `$authMgrPlus_role_capabilities` and `$authMgrPlus_anon_capabilities`. These are set to defaults in the `authMgrPlus_env_check()` function.

#### NOTE:
This is a fork of nicwaller's [Authmgr](https://github.com/nicwaller/yourls-authmgr-plugin) merged with Ian barber's[Seperate User's](https://github.com/joshp23/Yourls-Separate-Users) plugin. Both code bases underwent heavy rewrites, and have been extensively updated and tightly integrated here, resulting in a lean and highly functional user authorization management environment.

### Support Dev
All of my published code is developed and maintained in spare time, if you would like to support development of this, or any of my published code, I have set up a Liberpay account for just this purpose. Thank you.

<noscript><a href="https://liberapay.com/joshu42/donate"><img alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a></noscript>

License
-------
Copyright 2018 Joshua Panter  
Copyright 2013 Nicholas Waller (code@nicwaller.com)  
Copyright 2011 Ian Barber  
