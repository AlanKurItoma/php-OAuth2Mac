<?php namespace OAuth2Mac;
/** @package OAuth2MAC  Provides useful classes and functionality for 
  *                     creating and validating MAC signatures.
  */

/**
 * OAuth 2.0 MAC Token Utility Class
 *
 * Generates MAC signatures from supplied information
 */
class OAuth2MacTokenUtil {

    /**
     * Generate Authorization Request Header String
     * @param string $key_id MAC key identifier
     * @param string $key MAC key
     * @param string $algorithm MAC algorithm
     * @param int $timestamp Timestamp of request
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $ext "ext" "Authorization" request header field attribute
     * @return string
     */
    public static function genetateAuthZHeader($key_id, $key, $algorithm, $timestamp, $nonce=null, $method, $url, $ext=null) {

        // Check MAC Credentials
        if (empty($key_id) || empty($key) || empty($algorithm) || (empty($nonce) && empty($timestamp))) {
            throw new Exception('Missing MAC Credentials');
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonceStr($timestamp);
        }

        // Check request data
        if (empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        // Process entity-body
        $mac = self::generateMac($key_id, $key, $algorithm, $timestamp, $nonce, $method, $url, $ext);
        return self::_buildAuthZHeaderStr($key_id, $nonce, $ext, $mac);
    }

    /**
     * Generate MAC String
     * @param string $key_id MAC key identifier
     * @param string $key MAC key
     * @param string $algorithm MAC algorithm
     * @param int $timestamp
     * @param string $nonce
     * @param string $method
     * @param string $url
     * @param string $ext "ext" "Authorization" request header field attribute
     * @return string
     */
    public static function generateMac($key_id, $key, $algorithm, $timestamp, $nonce=null, $method, $url, $ext=null) {

        // Check MAC Credentials
        if (empty($key_id) || empty($key) || empty($algorithm) || (empty($nonce) && empty($timestamp))) {
            throw new Exception('Missing MAC Credentials');
        }

        // Process nonce
        if (empty($nonce)) {
            $nonce = OAuth2Util::generateNonceStr($timestamp);
        }

        // Check request data
        if (empty($method) || empty($url)) {
            throw new Exception('Missing Params');
        }

        $host = "";
        $port = "";
        $request_uri = "";
        $urlinfo = parse_url($url);

        if (!$urlinfo) {
            throw new Exception('Invalid URL');
        } else {
            if ($urlinfo['scheme'] != 'https' && $urlinfo['scheme'] != 'http') {
                throw new Exception('Invalid URL Scheme');
            }
            $host = $urlinfo['host'];
            if (isset($urlinfo['port']) && !empty($urlinfo['port'])) {
                $port = $urlinfo['port'];
            } else {
                if ($urlinfo['scheme'] == 'https') {
                    $port = '443';
                } else if ($urlinfo['scheme'] == 'http') {
                    $port = '80';
                }
            }
            $request_uri = substr($url,strpos($url,$urlinfo['path']));
        }

        $basestr = $timestamp . "\n" .
                $nonce . "\n" .
                $method . "\n" .
                $request_uri . "\n" .
                $host . "\n" .
                $port . "\n" .
                $ext . "\n";
        return self::_calculateMac($basestr, $key, $algorithm);
    }

    /**
     * Generate Authorization Header Request String from Paramaters
     * @param string $key_id
     * @param string $nonce
     * @param int $timestamp
     * @param string $ext
     * @param string $mac
     * @return string
     */
    private static function _buildAuthZHeaderStr($key_id, $nonce, $timestamp, $ext, $mac) {
        $header = 'Authorization: MAC id="' . $key_id . '",';
        $header .= 'nonce="' . $nonce . '",';
        $header .= 'ts="' . $timestamp . '",';

        If (!empty($ext)) {
            $header .= 'ext="' . $ext . '",';
        }
        $header .= 'mac="' . $mac . '"';
        return $header;
    }

}

/**
  * Basic utility functions for the MAC generation
  */
class OAuth2Util {

    public static function generateTimestamp() {
        $current = time();
    }

    public static function generateRandStr() {
        $mt = microtime();
        $rand = mt_rand();
        return md5($mt . $rand);
    }

    public static function generateNonceStr($iss, $current = null) {
        return self::generateAge($iss, $current) . ":" . self::generateRandStr();
    }
}

