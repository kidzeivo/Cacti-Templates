<?php
 

/* do NOT run this script through a web browser */
if (!isset($_SERVER["argv"][0]) || isset($_SERVER['REQUEST_METHOD'])  || isset($_SERVER['REMOTE_ADDR'])) {
	die("<br><strong>This script is only meant to run at the command line.</strong>");
}

$no_http_headers = true;

/* display No errors */
error_reporting(0);

if (isset($config)) {
	include_once(dirname(__FILE__) . "/../lib/snmp.php");
}

if (!isset($called_by_script_server)) {
	include_once(dirname(__FILE__) . "/../include/global.php");
	include_once(dirname(__FILE__) . "/../lib/snmp.php");

	array_shift($_SERVER["argv"]);

	print call_user_func_array("ss_juniper_int_qstats", $_SERVER["argv"]);
}

function ss_juniper_int_qstats($hostname, $snmp_auth, $cmd, $query_field="", $query_index="") { 

	$snmp = explode(":", $snmp_auth);
	$snmp_version 		= $snmp[0];
	$snmp_port    		= $snmp[1];
	$snmp_timeout 		= $snmp[2];
	$ping_retries 		= $snmp[3];
	$max_oids		= $snmp[4];

	$snmp_auth_username   	= "";
	$snmp_auth_password   	= "";
	$snmp_auth_protocol  	= "";
	$snmp_priv_passphrase 	= "";
	$snmp_priv_protocol   	= "";
	$snmp_context         	= "";
	$snmp_community 	= "";

	if ($snmp_version == 3) {
		$snmp_auth_username   = $snmp[6];
		$snmp_auth_password   = $snmp[7];
		$snmp_auth_protocol   = $snmp[8];
		$snmp_priv_passphrase = $snmp[9];
		$snmp_priv_protocol   = $snmp[10];
		$snmp_context         = $snmp[11];
	}else{
		$snmp_community = $snmp[5];
	}
		
# define all OIDs we need for further processing
$oids = array(
        "index"         		=> ".1.3.6.1.2.1.2.2.1.1",
        "ifstatus"      		=> ".1.3.6.1.2.1.2.2.1.8",
        "ifdescription" 		=> ".1.3.6.1.2.1.2.2.1.2",
        "ifname"        		=> ".1.3.6.1.2.1.31.1.1.1.1",
        "ifalias"      			=> ".1.3.6.1.2.1.31.1.1.1.18",
        "iftype"        		=> ".1.3.6.1.2.1.2.2.1.3",
        "ifspeed"       		=> ".1.3.6.1.2.1.2.2.1.5",
        "ifHWaddress"   		=> ".1.3.6.1.2.1.2.2.1.6",
        "jnxCosIfqQedPkts"    		=> ".1.3.6.1.4.1.2636.3.15.4.1.3",
        "jnxCosIfqTxedPkts"   		=> ".1.3.6.1.4.1.2636.3.15.4.1.7",
	"jnxCosIfqTailDropPkts"   	=> ".1.3.6.1.4.1.2636.3.15.4.1.11",
	"jnxCosQstatQedBytes"   	=> ".1.3.6.1.4.1.2636.3.15.4.1.5",
	"jnxCosQstatTotalRedDropPkts"   => ".1.3.6.1.4.1.2636.3.15.4.1.13",
	"jnxCosQstatRateLimitDropPkts"	=> ".1.3.6.1.4.1.2636.3.15.4.1.49",
        );
	
# define all values queues queue queries
$qstats_arr = array(
        "queued1"	=> "0",
        "queued2"	=> "1",
        "queued3"	=> "2",
        "queued4"	=> "3",
        "queued5"	=> "4",
        "queued6"	=> "5",
        "queued7"	=> "6",
	"queued8"	=> "7",
        "transmitted1"	=> "0",
        "transmitted2"	=> "1",
        "transmitted3" 	=> "2",
        "transmitted4"	=> "3",
        "transmitted5"	=> "4",
        "transmitted6"	=> "5",
        "transmitted7"	=> "6",
	"transmitted8"	=> "7",
        "dropped1"	=> "0",
        "dropped2"	=> "1",
        "dropped3" 	=> "2",
        "dropped4"	=> "3",
        "dropped5"	=> "4",
        "dropped6"	=> "5",
        "dropped7"	=> "6",
	"dropped8"	=> "7",
        "reddropped1"	=> "0",
        "reddropped2"	=> "1",
        "reddropped3" 	=> "2",
        "reddropped4"	=> "3",
        "reddropped5"	=> "4",
        "reddropped6"	=> "5",
        "reddropped7"	=> "6",
	"reddropped8"	=> "7",
        "ratelimitdropped1"	=> "0",
        "ratelimitdropped2"	=> "1",
        "ratelimitdropped3" 	=> "2",
        "ratelimitdropped4"	=> "3",
        "ratelimitdropped5"	=> "4",
        "ratelimitdropped6"	=> "5",
        "ratelimitdropped7"	=> "6",
	"ratelimitdropped8"	=> "7",
        "queuedbytes1"	=> "0",
        "queuedbytes2"	=> "1",
        "queuedbytes3" 	=> "2",
        "queuedbytes4"	=> "3",
        "queuedbytes5"	=> "4",
        "queuedbytes6"	=> "5",
        "queuedbytes7"	=> "6",
	"queuedbytes8"	=> "7",
        );
	
$xml_delimiter          =  "!";
$snmp_context = "";
$indices_arr = array();
 
# get number of snmp retries from global settings
$snmp_retries   = read_config_option("snmp_retries");
# -------------------------------------------------------------------------
# script MUST respond to index queries
#       the command for this is defined within the XML file as
#       <arg_index>index</arg_index>
#       you may replace the string "index" both in the XML and here
# -------------------------------------------------------------------------
#       php -q <script> <parms> index
# will all indices of the target values
# e.g. in case of interfaces
#      it has to respond with the list of interface indices
# -------------------------------------------------------------------------
if ($cmd == "index") {
        # retrieve all indices from target
        $return_arr_index = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["index"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	
	$return_arr_iftype = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["iftype"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	
	$return_arr_ifdescription = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["ifdescription"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
 
        # and print each index as a separate line
        for ($i=0;($i<sizeof($return_arr_index));$i++) {
		if ($return_arr_iftype[$i] == 6 and (preg_match("/^[gx].*/",$return_arr_ifdescription[$i]))){
                	print $return_arr_index[$i] . "\n";
		}
        }
#
# -------------------------------------------------------------------------
# script MUST respond to query requests
#       the command for this is defined within the XML file as
#       <arg_query>query</arg_query>
#       you may replace the string "query" both in the XML and here
# -------------------------------------------------------------------------
#       php -q <script> <parms> query <function>
# where <function> is a parameter that tells this script,
# which target value should be retrieved
# e.g. in case of interfaces, <function> = ifdescription
#      it has to respond with the list of
#      interface indices along with the description of the interface
# -------------------------------------------------------------------------
}elseif ($cmd == "query" && isset($query_field)) {

        # retrieve all indices from target
        $return_arr_index = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["index"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	
	$return_arr_iftype = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["iftype"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	
	$return_arr_ifdescription = ss_juniper_int_qstats_reindex(cacti_snmp_walk($hostname, $snmp_community,
        $oids["ifdescription"], $snmp_version, $snmp_auth_username,
        $snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        $snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
 
        # and print each index as a separate line
        for ($i=0;($i<sizeof($return_arr_index));$i++) {
		if ($return_arr_iftype[$i] == 6 and (preg_match("/^[gx].*/",$return_arr_ifdescription[$i]))){
                	$indices_arr[] = $return_arr_index[$i];
		}
        }

        for ($i=0;($i<sizeof($indices_arr));$i++) {
		if (preg_match("/^queued[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosIfqQedPkts"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} elseif (preg_match("/^transmitted.[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosIfqTxedPkts"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} elseif (preg_match("/^dropped[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosIfqTailDropPkts"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} elseif (preg_match("/^reddropped[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosQstatTotalRedDropPkts"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} elseif (preg_match("/^ratelimitdropped[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosQstatRateLimitDropPkts"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} elseif (preg_match("/^queuedbytes[1-8]$/",$query_field)){
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids["jnxCosQstatQedBytes"] . ".$indices_arr[$i]." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		} else  {
			$result = cacti_snmp_get($hostname, $snmp_community,
        		$oids[$query_field] . ".$indices_arr[$i]", $snmp_version, $snmp_auth_username,
        		$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        		$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER);
		}
		
                print $indices_arr[$i] . $xml_delimiter . $result . "\n";
        }	
	

# -------------------------------------------------------------------------
# script MUST respond to get requests
#       the command for this is defined within the XML file as
#       <arg_get>get</arg_get>
#       you may replace the string "get" both in the XML and here
# -------------------------------------------------------------------------
#       php -q <script> <parms> get <function> <index>
# where <function> is a parameter that tells this script,
# which target value should be retrieved
# and   <index>    is the index that should be queried
# e.g. in case of interfaces, <function> = ifdescription
#                             <index>    = 1
#      it has to respond with
#      the description of the interface for interface #1
# -------------------------------------------------------------------------
}elseif ($cmd == "get" && isset($query_field) && isset($query_index)) {
	if (preg_match("/^queued[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosIfqQedPkts"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} elseif (preg_match("/^transmitted[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosIfqTxedPkts"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} elseif (preg_match("/^dropped[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosIfqTailDropPkts"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} elseif (preg_match("/^reddropped[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosQstatTotalRedDropPkts"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} elseif (preg_match("/^ratelimitdropped[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosQstatRateLimitDropPkts"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} elseif (preg_match("/^queuedbytes[1-8]$/",$query_field)){
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids["jnxCosQstatQedBytes"] . ".$query_index." . "$qstats_arr[$query_field]", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	} else {	
        	return (cacti_snmp_get($hostname, $snmp_community,
        	$oids[$query_field] . ".$query_index.", $snmp_version, $snmp_auth_username,
        	$snmp_auth_password, $snmp_auth_protocol, $snmp_priv_passphrase, $snmp_priv_protocol,
        	$snmp_context, $snmp_port, $snmp_timeout, $snmp_retries, $max_oids, SNMP_POLLER));
	}
# -------------------------------------------------------------------------
# -------------------------------------------------------------------------
} else {
        print "Invalid use of script query, required parameters:\n\n";
        print "    <hostname> <community> <version> <snmp_port> <timeout> 
                   <max_oids> <auth_user> <auth_passphrase> <auth_proto>
                   <priv_passphrase> <priv_proto> <context> <cmd>\n";
}



}



function ss_juniper_int_qstats_reindex($arr) {
        $return_arr = array();
 
        for ($i=0;($i<sizeof($arr));$i++) {
                $return_arr[$i] = $arr[$i]["value"];
        }
 
        return $return_arr;
}
?>
 
