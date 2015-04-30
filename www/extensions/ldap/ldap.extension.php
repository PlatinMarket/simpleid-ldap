<?php

require_once "ldap.php";

function ldap_user_verify_credentials($uid, $credentials) {
  $test_user = user_load($uid);
  
  if ($test_user == NULL) return false;

  if (isset($test_user["auth_method"]) && $test_user["auth_method"] != "ldap") return;

  if ($ldap = ldap_custom_connect()) {
    try {
      if (!$ldap->authenticate($uid, $credentials["pass"])) return false;
      if (($ad_user = $ldap->user_info($uid)) === false) return false;

      $test_user["member_of"] = $ad_user['memberof'];
      $test_user["user_info"] = array('uid' => $ad_user['uid'], 'nickname' => $ad_user['uid'], 'name' => $ad_user['cn'], 'email' => $ad_user['mail'], 'memberof' => implode(",", $ad_user['memberof']));
      user_save($test_user);
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

function ldap_page_profile() {

}


?>
