<?php

/*

The MIT License (MIT)

Copyright (c) 2015 Jan Knipper <j.knipper@part.berlin>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

SOURCE: https://github.com/jknipper/htaccess-banip


 */

/*
 * Settings
 */

const MAX_RETRY = 1000;
const FIND_TIME = 86400; //in seconds

const IP_DB_FILE  = __DIR__ ."/ban_ip_db.txt";




//secure db file
//chmod($ip_db_file,0600);

/*
 * Functions
 */


function dirname_safe($path, $level = 0){
    $dir = explode(DIRECTORY_SEPARATOR, $path);
    $level = $level * -1;
    if($level == 0) $level = count($dir);
    array_splice($dir, $level);
    return implode($dir, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR;
}

function check_ip( $ip ) {

	$ban = false;
	$db  = array();

	if ( file_exists( IP_DB_FILE ) ) {
		$db = load();
	}

	if ( ! empty( $db ) && array_key_exists( $ip, $db ) ) {

		$tdiff = time() - $db[ $ip ]["timestamp"];

		if ( $db[ $ip ]["retries"] >= MAX_RETRY && $tdiff <= FIND_TIME ) {
			$ban = true;
			$db[ $ip ]["retries"]=$db[ $ip ]["granted_retries"];
		} elseif ( $tdiff > FIND_TIME ) {
			$db[ $ip ]["timestamp"] = time();
			$db[ $ip ]["retries"]   = 1;
		} else {
			$db[ $ip ]["timestamp"] = time();
			$db[ $ip ]["retries"]   = $db[ $ip ]["retries"] + 1;
		}
	} else {
		$db[ $ip ] = array( "timestamp" => time(), "retries" => 1 ,"granted_retries" => MAX_RETRY);
	}

	save( $db );

	return $ban;
}

function ban_ip( $ip ) {
	$deny = sprintf( "\nDENY FROM %s", $ip );
	file_put_contents( dirname_safe(__DIR__, 1) . ".htaccess", $deny, FILE_APPEND );
}

function load() {
	return unserialize( file_get_contents( IP_DB_FILE ) );
}

function save( $data ) {
	return file_put_contents( IP_DB_FILE, serialize( $data ) );
}

function get_ip() {
	global $_SERVER;
	$ip = null;

	if ( ! empty( $_SERVER['HTTP_CLIENT_IP'] ) ) {
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$ip = $_SERVER['REMOTE_ADDR'];
	}

	return $ip;
}

/*
 * Get IP Address
 */

$ip = get_ip();

/*
 * Check IP and ban after MAX_RETRY
 */

if ( filter_var( $ip, FILTER_VALIDATE_IP ) && check_ip( $ip ) ) {
	//Ban him and tell him
	ban_ip( $ip );

	//send response
	http_response_code( 401 );
	
	echo '
	<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
	<html>
	<head>
		<title>401 Authorization Required</title>
	</head>
	<body>
	<h1>Authorization Required</h1>
	
	<p>This server could not verify that you
		are authorized to access the document
		requested. Either you supplied the wrong
		credentials (e.g., ba2003:45:4b35:500:9dc0:f1a3:8f8f:7797d password), or your
		browser doesnt understand how to supply
		the credentials required.</p>
	</body>
	</html>';


	//Throw exception
	throw new Exception('You are not allowed to do this.');

	// Stop script
	die();
}

/*
 * Send response
 */



?>
