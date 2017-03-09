<?php
/**
* Lansuite sessin auth plug-in for phpBB3
*
* @package login
* @version $Id$
* @copyright (c) 2005 phpBB Group
* @license http://opensource.org/licenses/gpl-license.php GNU Public License
*
*/



namespace phpbb\auth\provider;

/**
* Lansuite authentication provider for phpBB3
*/
class lansuite extends \phpbb\auth\provider\base
{
	/**
	* phpBB passwords manager
	*
	* @var \phpbb\passwords\manager
	*/
	protected $passwords_manager;

	/**
	 * Apache Authentication Constructor
	 *
	 * @param	\phpbb\db\driver\driver_interface 	$db		Database object
	 * @param	\phpbb\config\config 		$config		Config object
	 * @param	\phpbb\passwords\manager	$passwords_manager		Passwords Manager object
	 * @param	\phpbb\request\request 		$request		Request object
	 * @param	\phpbb\user 			$user		User object
	 * @param	string 				$phpbb_root_path		Relative path to phpBB root
	 * @param	string 				$php_ext		PHP file extension
	 */
	public function __construct(\phpbb\db\driver\driver_interface $db, \phpbb\config\config $config, \phpbb\passwords\manager $passwords_manager, \phpbb\request\request $request, \phpbb\user $user, $phpbb_root_path, $php_ext)
	{
		$this->db = $db;
		$this->config = $config;
		$this->passwords_manager = $passwords_manager;
		$this->request = $request;
		$this->user = $user;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;
	}

	/**
	 * {@inheritdoc}
	 */
	public function init()
	{

		$sql = 'show columns from '.USERS_TABLE.' where field like "user_uuid"';
		$result = $this->db->sql_query($sql);
		$user_uuid_notexists = $result->num_rows === 1;
		$this->db->sql_freeresult($result);
		var_dump ($user_uuid_exists);

		if ($user_uuid_notexists)
		{	
			$sql = "ALTER TABLE ".USERS_TABLE." 
				ADD COLUMN `user_uuid` INT(11)" ;
			$result = $this->db->sql_query($sql);
			$success = $result;
			$this->db->sql_freeresult($result);
		
			if (!$success) return $this->user->lang['LANSUITE_SETUP_TABLE_ERROR'];
		}
	
		//Start Session mgmt to Read lansuite session data
		$this->request->enable_super_globals();
		session_start();   	
		$this->request->disable_super_globals();


	
		if (strtolower($this->user->data['username']) !== strtolower(htmlspecialchars_decode($_SESSION['auth']['username'])))
		{
			
			return $this->user->lang['LANSUITE_SETUP_BEFORE_USE'];
		}
		return false;
	}

	/**
	 * {@inheritdoc}
	 */
	public function login($username, $password)
	{	

		$this->request->enable_super_globals();
		session_start();   	
		$this->request->disable_super_globals();

		if (!isset($_SESSION['auth']['userid']))
		{
			return array(
					'status'	=> LOGIN_ERROR_USERNAME,
					'error_msg'	=> 'LOGIN_ERROR_USERNAME',
					'user_row'	=> array('user_id' => ANONYMOUS),
				);
		}

		$php_auth_user = $_SESSION['auth']['userid'];

		if (!empty($php_auth_user))
		{
			if ($_SESSION['auth']['username'] !== $username)
			{
				return array(
					'status'	=> LOGIN_ERROR_USERNAME,
					'error_msg'	=> 'LOGIN_ERROR_USERNAME',
					'user_row'	=> array('user_id' => ANONYMOUS),
				);
			}

			$sql = 'SELECT user_id, username, user_password, user_passchg, user_email, user_type
				FROM ' . USERS_TABLE . "
				WHERE user_uuid = '" . $this->db->sql_escape($php_auth_user) . "'";
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);
				return array(
					'status'		=> LOGIN_SUCCESS,
					'error_msg'		=> false,
					'user_row'		=> $row,
				);

			if ($row)
			{
				// User inactive...
				if ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE)
				{
					return array(
						'status'		=> LOGIN_ERROR_ACTIVE,
						'error_msg'		=> 'ACTIVE_ERROR',
						'user_row'		=> $row,
					);
				}

				// Successful login...
				return array(
					'status'		=> LOGIN_SUCCESS,
					'error_msg'		=> false,
					'user_row'		=> $row,
				);
			}

			// this is the user's first login so create an empty profile
			return array(
				'status'		=> LOGIN_SUCCESS_CREATE_PROFILE,
				'error_msg'		=> false,
				'user_row'		=> $this->user_row($php_auth_user, $php_auth_pw),
			);
		}

		// Not logged into apache
		return array(
			'status'		=> LOGIN_ERROR_EXTERNAL_AUTH,
			'error_msg'		=> 'LOGIN_ERROR_EXTERNAL_AUTH_APACHE',
			'user_row'		=> array('user_id' => ANONYMOUS),
		);
	}

	/**
	 * {@inheritdoc}
	 */
	public function autologin()
	{

		//Start Session mgmt to Read lansuite session data
		$this->request->enable_super_globals();
		session_start();   	
		$this->request->disable_super_globals();

		if (!isset($_SESSION['auth']['userid']))
		{
			return array();
		}

		$php_auth_user = $_SESSION['auth']['userid'];
		if(isset($_SESSION['auth']['userid']))
		{
			set_var($php_auth_user, $php_auth_user, 'string', true);

			$sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE user_uuid = '" . $this->db->sql_escape($php_auth_user) . "'";
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);

			if($row['user_email']!==$_SESSION['auth']['email'] || $row['username'] !== $_SESSION['auth']['username'])
			{
				$sql = 'UPDATE ' . USERS_TABLE. " SET username = '" . $this->db->sql_escape($_SESSION['auth']['username']) . "' WHERE user_uuid = '" . $this->db->sql_escape($php_auth_user) . "'";
				$result = $this->db->sql_query($sql);
				$this->db->sql_freeresult($result);

				$sql = 'UPDATE ' . USERS_TABLE. " SET username_clean = '" . $this->db->sql_escape($_SESSION['auth']['username']) . "' WHERE user_uuid = '" . $this->db->sql_escape(utf8_clean_string($php_auth_user)) . "'";
				$result = $this->db->sql_query($sql);
				$this->db->sql_freeresult($result);

				$sql = 'UPDATE ' . USERS_TABLE. " SET user_email = '" . $this->db->sql_escape($_SESSION['auth']['email']) . "' WHERE user_uuid = '" . $this->db->sql_escape($php_auth_user) . "'";
				$result = $this->db->sql_query($sql);
				$this->db->sql_freeresult($result);

			}			
	
			if ($row)
			{
				return ($row['user_type'] == USER_INACTIVE || $row['user_type'] == USER_IGNORE) ? array() : $row;
			}

			if (!function_exists('user_add'))
			{
				include($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
			}

			// create the user if he does not exist yet
			user_add($this->user_row($php_auth_user));

			$sql = 'SELECT *
				FROM ' . USERS_TABLE . "
				WHERE user_uuid = '" . $this->db->sql_escape($php_auth_user) . "'";
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			$this->db->sql_freeresult($result);

			if ($row)
			{
				return $row;
			}
		}

		return array();
	}

	/**
	 * This function generates an array which can be passed to the user_add
	 * function in order to create a user
	 *
	 * @param 	string	$username 	The username of the new user.
	 * @param 	string	$password 	The password of the new user.
	 * @return 	array 				Contains data that can be passed directly to
	 *								the user_add function.
	 */
	private function user_row($username)
	{
		$this->request->enable_super_globals();
		session_start();   	
		$this->request->disable_super_globals();
		// first retrieve default group id
		$sql = 'SELECT group_id
			FROM ' . GROUPS_TABLE . "
			WHERE group_name = '" . $this->db->sql_escape('REGISTERED') . "'
				AND group_type = " . GROUP_SPECIAL;
		$result = $this->db->sql_query($sql);
		$row = $this->db->sql_fetchrow($result);
		$this->db->sql_freeresult($result);

		if (!$row)
		{
			trigger_error('NO_GROUP');
		}

		// generate user account data
		return array(
			'username'		=> $_SESSION['auth']['username'],
			'user_password'	=> $this->passwords_manager->hash($_SESSION['auth']['password']),
			'user_email'	=> $_SESSION['auth']['email'],
			'group_id'		=> (int) $row['group_id'],
			'user_type'		=> USER_NORMAL,
			'user_ip'		=> $this->user->ip,
			'user_new'		=> ($this->config['new_member_post_limit']) ? 1 : 0,
			'user_uuid'		=> $_SESSION['auth']['userid'],
			'user_jabber'		=> $_SESSION['auth']['xmpp'],
			
		);
	}
	/**
	 * {@inheritdoc}
	 */
	public function validate_session($user)
	{	

		//Start Session mgmt to Read lansuite session data
		$this->request->enable_super_globals();
		session_start();   	
		$this->request->disable_super_globals();

		// Check if $_SESSION auth userid is set and handle this case
		if (isset($_SESSION['auth']['userid']))
		{
			$php_auth_user = $_SESSION['auth']['userid'];
			return ($php_auth_user === $user['user_uuid']) ? true : false;
		}
		
		// PHP_AUTH_USER is not set. A valid session is now determined by the user type (anonymous/bot or not)
		if ($user['user_type'] == USER_IGNORE)
		{
			return true;
		}

		return false;
	}
}
