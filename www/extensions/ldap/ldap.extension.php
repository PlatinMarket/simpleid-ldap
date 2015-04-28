<?php

require_once "ldap.php";

function ldap_user_verify_credentials($uid, $credentials) {
  $test_user = user_load($uid);
  
  if ($test_user == NULL) return false;

  if ($ldap = ldap_custom_connect()) {
    try {
      if (!$ldap->authenticate($uid, $credentials["pass"])) return false;
      $users = $ldap->get_users();
      return in_array($uid, $users);
    } catch (Exception $e) {
      throwError($e);
    }
  }

}

function ldap_custom_connect() {
  try {
    $ldap = new LDAP(LDAP_URI, LDAP_BASE_DN, LDAP_SEARCH_DN, LDAP_BASE_DOMAIN);
    return $ldap;
  } catch (Exception $err) {
    throwError($err);
    return false;
  }
}

?>
