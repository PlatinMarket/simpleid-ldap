<?php

require_once "ldap.php";

function ldap_user_verify_credentials($uid, $credentials) {
  $user = user_load($uid);
  
  if ($user == NULL) return false;

  if (isset($user["auth_method"]) && $user["auth_method"] != "ldap") return;

  if ($ldap = ldap_custom_connect()) {
    try {
      if (!$ldap->authenticate($uid, $credentials["pass"])) return false;
      return true;
    } catch (Exception $e) {
      throwError($e);
    }
  }



}

function ldap_custom_connect() {
  try {
    $ldap = new LDAP(LDAP_URI, LDAP_BASE_DN, LDAP_ADMIN_DN, LDAP_ADMIN_PASSWORD);
    return $ldap;
  } catch (Exception $err) {
    throwError($err);
    return false;
  }
}

?>
