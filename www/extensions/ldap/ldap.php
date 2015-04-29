<?php

// The LDAP server
class LDAP
{
    private $server = "127.0.0.1";
    private $domain = "localhost";
    private $admin = "admin";
    private $password = "";
    private $baseDn = "";
    private $attributes = array("cn", "memberof", "samaccountname");
    private $baseDomain = "";

    public function __construct($server, $domain, $baseDn, $baseDomain)
    {
        $this->server = $server;
        $this->domain = $domain;
        $this->baseDn = $baseDn;
        $this->baseDomain = $baseDomain;
    }

    // Authenticate the against server the domain\username and password combination.
    public function authenticate($username, $password) {
        if (!$this->serviceping($this->server, 389, 2)) return false; // Check Service if alive
        
        $this->admin = $username;
        $this->password = $password;

        if (empty($password)) return false;
        $ldap = ldap_connect($this->server);
        if (!$ldap) return false;
        ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
        ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
        $ldapbind = @ldap_bind($ldap, $this->baseDomain . "\\" . $this->admin, $this->password);

        if($ldapbind) return true;

        ldap_close($ldap);
        return false;
    }

    private function serviceping($host, $port=389, $timeout=1) {
        $op = fsockopen($host, $port, $errno, $errstr, $timeout);
        if (!$op) {
            return false; //DC is N/A
        } else {
            fclose($opanak); //explicitly close open socket connection
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