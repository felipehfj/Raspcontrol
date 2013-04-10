<?php

namespace lib;

class Rbpi {
  
  public static function distribution() {
    $distroTypeRaw = exec("cat /etc/*-release | grep PRETTY_NAME=", $out);
    $distroTypeRawEnd = str_ireplace('PRETTY_NAME="', '', $distroTypeRaw);
    $distroTypeRawEnd = str_ireplace('"', '', $distroTypeRawEnd);

    return $distroTypeRawEnd;
  }

  public static function kernel() {
    return exec("uname -mrs");
  }

  public static function firmware() {
    return exec("uname -v");
  }

  public static function hostname() {
    return gethostname();
  }

  public static function ip($remote = false) {
    return $remote ? $_SERVER['SERVER_ADDR'] : $_SERVER['REMOTE_ADDR'];
  }

  public static function webServer() {
    return$_SERVER['SERVER_SOFTWARE'];
  }

}

?>