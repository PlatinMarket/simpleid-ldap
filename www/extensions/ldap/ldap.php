<?php

// The LDAP server
class LDAP
{
    private $server = null;
    private $adminDn = null;
    private $adminPassword = null;
    private $userPrefix = null;
    private $baseDn = "";
    private $attributes = array("cn", "memberof", "samaccountname");

    private function ldapConnect(){
        if (!$this->serviceping($this->server, 389, 2)) return false; // Check Service if alive
        $ldap = @ldap_connect($this->server);
        if (!$ldap) return false;
        return $ldap;
    }
    private function bindLdap($ldap, $username = null, $password = null){
        $username = $username ? $username : $this->adminDn;
        $password = $password ? $password : $this->adminPassword;
    
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);

        $ldapbind = @ldap_bind($ldap, $this->userPrefix . "\\" . $username, $password);
        if ($ldapbind) return true;
        return false;
    }

    function __construct($server, $baseDn, $adminDn, $adminPassword) {
        $this->server = $server;
        $this->baseDn = $baseDn;
        $this->adminDn = $adminDn;
        $this->adminPassword = $adminPassword;
        $parts = ldap_explode_dn($this->baseDn, 1);
        unset($parts['count']);
        $this->userPrefix = strtoupper($parts[0]);
    }

    // Authenticate the against server the domain\username and password combination.
    public function authenticate($username, $password) {
        if (($ldap = $this->ldapConnect()) == false) return false;

        $result = $this->bindLdap($ldap, $username, $password);
        ldap_close($ldap);
        
        return $result;
    }

    public function user_info($uid){
        if (($ldap = $this->ldapConnect()) == false) return false;

        if (!$this->bindLdap($ldap)) return false;

        $user = array('uid' => $uid);
        $sr = ldap_search($ldap, $this->baseDn, "(&(sAMAccountName=" . $uid . ")(objectclass=person))");
        $info = ldap_get_entries($ldap, $sr);

        if ($info["count"] == 0) return false;

        $temp_user = array();
        foreach ($info[0] as $key => $value) if (is_string($key)) $temp_user[$key] = $value;

        $user['cn'] = $temp_user['cn'][0];
        $user['dn'] = $temp_user['distinguishedname'][0];
        $user['mail'] = isset($temp_user['mail']) ? $temp_user['mail'][0] : "";
        $user['memberof'] = array();
        foreach ($temp_user['memberof'] as $key => $value) if (!is_string($key)) $user['memberof'][] = ldap_explode_dn($value, 1)[0];

        ldap_close($ldap);
        return $user;
    }

    private function serviceping($host, $port=389, $timeout=1) {
        $op = fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$op) {
            return false; //DC is N/A
        } else {
            fclose($op); //explicitly close open socket connection
            return true; //DC is up & running, we can safely connect with ldap_connect
        }
    }

    // Get an array of users or return false on error
    public function get_users() {       
        if (!$this->serviceping($this->server, 389, 2)) return false; // Check Service if alive
        
        if(!($ldap = ldap_connect($this->server))) return false;

        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        $ldapbind = ldap_bind($ldap, $this->baseDomain . "\\" . $this->admin, $this->password);

        $base_dn = $this->baseDn;
        $sr=ldap_search($ldap, $this->domain, "(&(memberof=" . $base_dn . "))", $this->attributes);
        $info = ldap_get_entries($ldap, $sr);
       
        $users = array();
        for($i = 0; $i < $info["count"]; $i++) {
            $users[] = $info[$i]["samaccountname"][0];
        }
        return $users;
    }
}
?>