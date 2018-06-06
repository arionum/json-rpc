<?php

require_once(__DIR__. '/vendor/autoload.php');

use Dotenv\Dotenv;
use Dotenv\Exception\InvalidPathException;
use BitWasp\BitcoinLib\BitcoinLib;
use BitWasp\BitcoinLib\RawTransaction;

error_reporting(0);
ob_start();

try {
    $dotenv = new Dotenv(__DIR__);
    $dotenv->load();
} catch (InvalidPathException $invalidPathException) {
    echo 'Please copy .env.example to .env and fill in your configuration.';
    exit();
}

set_include_path(getenv('NODE_PATH'));

require_once("include/config.inc.php");
require_once("include/db.inc.php");
require_once("include/functions.inc.php");
require_once("include/block.inc.php");
require_once("include/account.inc.php");
require_once("include/transaction.inc.php");

$db=new DB($_config['db_connect'],$_config['db_user'],$_config['db_pass'],0);
if(!$db) die("Could not connect to the Node DB backend.");


$rpc=new DB("mysql:host=localhost;dbname=".getenv('DB_NAME'),getenv('DB_USER'),getenv('DB_PASS'),0);
if(!$rpc) die("Could not connect to the RPC DB backend.");



if($argv[1]=="cron"){
	//cleaning the passphrase after expiration
	$exp=$rpc->single("SELECT val FROM wallet_config WHERE id='expiry'");
	if($exp<time()&&$exp>0){
		file_put_contents("/etc/aro/key",""); 
		$rpc->run("UPDATE wallet_config SET val=:val WHERE id='expiry'",array(":val"=>0));		
	}
exit;
}

$request_id="";

function recho($result=NULL, $error=NULL){
global $request_id;
echo json_encode(array("result"=>$result,"error"=>$error, "id"=>$request_id));

$bufferContent = ob_get_contents();
ob_end_flush();
// just some debug
//file_put_contents("x",$bufferContent);

exit;
}


$global_pub=$rpc->single("SELECT val FROM wallet_config WHERE id='public_key'");
$global_priv=$rpc->single("SELECT val FROM wallet_config WHERE id='private_key'");



if($argv[1]=="setup"&&strlen($global_pub)<30){
while($res!="no"&&$res!="yes")  $res = readline("Would you like to encrypt the wallet? (yes/no) ");

if($res=="yes"){
while(strlen($pass)<6) $pass= readline("Please enter the password (min 6 chars, no left/right spaces) ");
} 
		$args=array(    "private_key_bits" => 4086,
    				"private_key_type" => OPENSSL_KEYTYPE_RSA, 
				"digest_alg" => "sha512");

		$key1 = openssl_pkey_new($args);
		
		openssl_pkey_export($key1, $pvkey);
		
		$private_key= $pvkey;
	
		$pub = openssl_pkey_get_details($key1);
		
		$public_key = $pub['key'];
		echo "We suggest to backup your private key:\n$private_key";

	if(strlen($pass)>3){
		
		$cipher = "aes-128-cbc";
		if (in_array($cipher, openssl_get_cipher_methods()))
		{
			$key=hash("sha256",getenv('GLOBAL_KEY').$pass);
			echo "\nFinal Key: $key\n";
    			$ivlen = openssl_cipher_iv_length($cipher);
    			$iv = openssl_random_pseudo_bytes($ivlen);
    			$ciphertext = openssl_encrypt($private_key, $cipher, $key, $options=0, $iv);
			$private_key=$ciphertext;
			$rpc->run("UPDATE wallet_config SET val=:val WHERE id='iv'",array(":val"=>base64_encode($iv)));
		}

	}


	$rpc->run("UPDATE wallet_config SET val=:val WHERE id='public_key'",array(":val"=>$public_key));
	$rpc->run("UPDATE wallet_config SET val=:val WHERE id='private_key'",array(":val"=>$private_key));


	echo "All set";
exit;
}
$decrypted=0;
if(strlen($global_pub)<30) recho(NULL,array("code"=>-1, "message"=>"Setup not completed"));



if(str_replace("-----BEGIN PRIVATE KEY-----","",$global_priv)!=$global_priv) { $decrypted=1; }
else {


$f=file_get_contents("/etc/aro/key");
if(strlen($f)>6){
$f=trim($f);
$key=hash("sha256",getenv('GLOBAL_KEY').$f);
$cipher = "aes-128-cbc";
$iv=$rpc->single("SELECT val FROM wallet_config WHERE id='iv'");

$global_priv = openssl_decrypt($global_priv, $cipher, $key, $options=0, base64_decode($iv));
if(str_replace("-----BEGIN PRIVATE KEY-----","",$global_priv)!=$global_priv) { $decrypted=1; }
// temporary key, decrypt
}
}

function pay_post($url, $data=array()){
        $peer="http://127.0.0.1";
    $postdata = http_build_query(
        array(
            'data' => json_encode($data),
            "coin"=>" arionum"
            )
    );

    $opts = array('http' =>
        array(
            'timeout' => "300",
            'method'  => 'POST',
            'header'  => 'Content-type: application/x-www-form-urlencoded',
            'content' => $postdata
        )
    );

    $context  = stream_context_create($opts);

    $result = file_get_contents($peer.$url, false, $context);
    $res=json_decode($result,true);
    return $res;


}



function getBalance($acc="", $export=false){
	global $db, $rpc;
	$bind=array();
	$whr="";
	if($acc!=="*"){
		$whr=" WHERE acc=:acc";
		$bind=array(":acc"=>$acc);
	}
	$r=$rpc->run("SELECT address FROM wallets $whr",$bind);
	$bal=0;
	$val=0;
	$adr=array();
	foreach($r as $x){
		$val=$db->single("SELECT balance FROM accounts WHERE id=:id",array(":id"=>$x['address']));
		$val-=$db->single("SELECT SUM(val+fee) FROM mempool WHERE src=:src",array(":src"=>$x['address'])); 
		if($val<0) $val=0;
		$bal+=$val;
		if($export) $adr[$x[address]]=$val;
	}
	if($export) return array("balance"=>$bal,"addresses"=>$adr);
	return number_format($bal,8,".","");
}

$rawData = file_get_contents("php://input");
$data=json_decode($rawData,true);

$request_id=$data['id'];

$method=$data['method'];
$params=$data['params'];
switch($method){
	case "getblockcount":
		$current=$db->single("SELECT height FROM blocks ORDER by height DESC LIMIT 1");
		recho($current);
		break;
	case "getblockhash":
		$p1=san($params[0]);
		 $hash=$db->single("SELECT id FROM blocks WHERE height=:height LIMIT 1",array(":height"=>$p1));
		if($hash===false) recho(NULL,array("code"=>-8, "message"=>"Block height out of range"));
		else recho($hash);
		break;
	case "getblock":
		$id=san($params[0]);
		$block=$db->row("SELECT * FROM blocks WHERE id=:id LIMIT 1",array(":id"=>$id));
		if(!$block) recho(NULL,array("code"=>-5, "message"=>"Block not found"));
		$current=$db->single("SELECT height FROM blocks ORDER by height DESC LIMIT 1");
		$confirmations=$current-$block['height'];
		$r=$db->run("SELECT * FROM transactions WHERE block=:id AND version>0 ORDER by id ASC",array(":id"=>$id));
		$trx=array();
		$transactions=json_encode($r);
		$size=strlen(json_encode($block).$transactions);
		$merkle=hash("sha256",$transactions);
		foreach($r as $x){
			$trx[]=$x['id'];
		}
		$prev=$db->row("SELECT * FROM blocks WHERE height=:height LIMIT 1",array(":height"=>$block['height']-1));
		$blocktime=$block['date']-$prev['date'];
		$mediantime=ceil(($block['date']-1515324995)/$block['height']);
		$next=$db->single("SELECT id FROM blocks WHERE height=:height LIMIT 1",array(":height"=>$block['height']+1));
		$res=array("hash"=>$block['id'],
			"confirmations"=>$confirmations,
			"size"=>$size,
			"strippedsize"=>$size,
			"weight"=>$size,
			"height"=>$block['height'],
			"version"=>"1",
			"versionHex"=>"01",
			"merkleroot"=>$merkle,
			"tx"=>$trx,
			"time"=>$block['date'],
			"mediantime"=>$block['date'],
			"nonce"=>$block['nonce'],
			"difficulty"=>$block['difficulty'],
			"chainwork"=>$block['argon']);

		if($prev!==false) $res['previousblockhash']=$prev['id'];
		if($next!==false) $res['nextblockhash']=$next;		
		break;
	case "getinfo":
		$current=$db->row("SELECT * FROM blocks ORDER by height DESC LIMIT 1");

		$res=array("deprecation-warning"=>"...",
			"version"=>1,
			"protocolversion"=>1,
			"walletversion"=>1,
			"balance"=>getBalance()."",
			"blocks"=>$current['height'],
			"timeoffset"=>0,
			"connections"=>$db->single("SELECT COUNT(1) FROM peers WHERE reserve=0 and blacklisted<UNIX_TIMESTAMP()"),
			"proxy"=>"",
			"difficulty"=>$current['difficulty'],
			"testnet"=>false,
			"keypoololdest"=>1515324995,
			"keypoolsize"=>1,
			"paytxfee"=>"1.00000000",
			"relayfee"=>"0.00000001",
			"errors"=>"");
		break;

	case "getnetworkinfo": 
		$res=array("version"=>1,
			"subversion"=>"arionum1.0",
			"protocolversion"=>1,
			"localservices"=> "0",
			"localrelay"=>true,
			"timeoffset"=>0,
			"networkactive"=>true,
			"connections"=>$db->single("SELECT COUNT(1) FROM peers WHERE reserve=0 and blacklisted<UNIX_TIMESTAMP()"),
			"networks"=>array(array("name"=>"ipv4", "limited"=>false, "reachable"=>true, "proxy"=>"", "proxy_randomize_credentials"=>false),
					array("name"=>"ipv6", "limited"=>false, "reachable"=>false, "proxy"=>"", "proxy_randomize_credentials"=>false),
					array("name"=>"onion", "limited"=>true, "reachable"=>false, "proxy"=>"", "proxy_randomize_credentials"=>false)),
			"relayfee"=>"0.00000001",
			"incrementalfee"=>"0.00000001",
			"localaddresses"=>array("address"=>"127.0.0.1", "port"=>8332,"score"=>10000),
			"warnings"=>"");
		break;		
	case "validateaddress":
		$params[0]=trim($params[0]);
		 $p1=san($params[0]);
		if($p1!=$params[0]) recho(array("isvalid"=>false));
		    $dst_b=base58_decode($p1);
    		    if(strlen($dst_b)!=64)  recho(array("isvalid"=>false));
			$ismine=false;
			if($rpc->single("SELECT COUNT(1) FROM wallets WHERE address=:id",array(":id"=>$p1))==1) $ismine=true;
		    $res=array("isvalid"=>true,
				"address"=>$p1,
				"scriptPubKey"=>bin2hex($dst_b),
				"ismine"=>$ismine,
				"iswatchonly"=>false,
				"isscript"=>false);
		break;	
	case "getbalance":
		//recho(getBalance("*",true));
		 $params[0]=trim($params[0]);
                 $p1=san($params[0],'*');
			$res=getBalance($p1);
		break;
	case "getnewaddress":
                $params[0]=trim($params[0]);
                 $p1=san($params[0]);
		$acc=new Account;
		$new=$acc->generate_account();
		if(strlen($new['private_key'])<30||strlen($new['public_key'])<30) recho(NULL,array("code"=>-10000,"message"=>"Could not generate a new address"));

		openssl_public_encrypt($new['private_key'], $fin, $global_pub);
		$new['private_key']=base64_encode($fin);

		$rpc->run("INSERT into wallets SET address=:address, public_key=:public_key, private_key=:private_key, data=UNIX_TIMESTAMP(), acc=:acc",
			array(":address"=>$new['address'],":public_key"=>$new['public_key'],":private_key"=>$new['private_key'],":acc"=>$p1));
		$check=$rpc->single("SELECT COUNT(1) FROM wallets WHERE address=:address AND public_key=:public_key AND private_key=:private_key AND data=UNIX_TIMESTAMP() AND acc=:acc",
			array(":address"=>$new['address'],":public_key"=>$new['public_key'],":private_key"=>$new['private_key'],":acc"=>$p1));
		if($check!=1) recho(NULL,array("code"=>-10000,"message"=>"Could not generate a new address"));

		$res=$new['address'];
		break;
	case "listtransactions":
		$current=$db->row("SELECT * FROM blocks ORDER by height DESC LIMIT 1");	
		$params[0]=trim($params[0]);
                $p1=san($params[0],'*');
		$p2=intval($params[1]);
		$p3=intval($params[2]);
		if($p2<1) $p2=10;
		if($p3<1) $p3=0;
		$awhr=""; $bind=array();
		if($p1!='*'){
			$awhr=" WHERE acc=:acc";
			$bind=array(":acc"=>$p1);
		}
		$r=$rpc->run("SELECT address, public_key, acc FROM wallets $awhr",$bind);
		$max=$current['height']-5000;
		$whr="height>$max AND (1=2 ";
		$adr=array();
		foreach($r as $x){
			$a=san($x['address']);
			$p=san($x['public_key']);
			$whr.=" OR dst='$a' OR public_key='$p' ";

			$adr[$a]=$x['acc'];
			$adr[$p]=$x['acc'];
		}
		$whr.=")";
		$r=$db->run("SELECT * FROM transactions WHERE $whr ORDER by height,date DESC LIMIT $p3,$p2");

		$trx=array();
		foreach($r as $x){
   			$dst=$x['dst'];
                        $pub=$x['public_key'];

			$cat="send";
			$acc=$adr[$pub];
			$fee=0;
			if(isset($adr[$dst])&&isset($adr[$pub])) continue;
			if(isset($adr[$dst])){
				$cat="receive";
				$acc=$adr[$dst];
			} else {
				$x['val']*=-1;
                                $fee=number_format($x['fee']*-1,8,".","");

			}

			$t=array("account"=>$acc,
				"address"=>$dst,
				"category"=>$cat,
				"amount"=>number_format($x['val'],8,".",""),
				"vout"=>0);
			
				if($fee!=0) $t['fee']=$fee;
				$t['confirmations']=$current['height']-$x['height'];
				$t['blockhash']=$x['block'];
				$t['blockindex']=0;
				$t['blocktime']=$x['date'];
				$t['txid']=$x['id'];
				$t['walletconflicts']=array();
				$t['time']=$x['date'];
				$t['timereceived']=$x['date'];
				$t['bip125-replaceable']="no";
				$t['abandoned']=false;
				
			$trx[]=$t;
		}
		$res=$trx;
		break;
	case "getrawtransaction":

	$p1=san($params[0]);
	$x=$db->row("SELECT * FROM transactions WHERE id=:id and version=1",array(":id"=>$p1));
	if(!$x) $x=$db->row("SELECT * FROM mempool WHERE id=:id and version=1",array(":id"=>$p1));	
	if(!$x) recho(NULL,array("code"=>-5,"message"=>"No such mempool or blockchain transaction."));
$t=array (
  'txid' => $x['id'],
  'version' => '1',
  'vin' =>
  array (
    0 =>
    array (
      'txid' => $x['id'],
      'vout' => 0,
      'scriptSig' =>
      array (
        'asm' => $x['signature'],
        'hex' => bin2hex(base58_decode($x['public_key'])),
      ),
      'sequence' => 4294967295,
    ),
  ),
  'vout' =>
  array (
    0 =>
    array (
      'value' => $x['val']*100000000,
      'vout' => 0,
      'scriptPubKey' =>
      array (
        'asm' => 'OP_DUP OP_HASH160 '.$x['dst'].' OP_EQUALVERIFY OP_CHECKSIG',
        'hex' => bin2hex(base58_decode($x['dst'])),
        'type' => 'pubkeyhash',
        'reqSigs' => 1,
        'hash160' => $x['dst'],
        'addresses' =>
        array (
          0 => $x['dst'],
        ),
      )
    ),
  ),
  'locktime' => '0',
);

$p2=trim($params[1]);
if($p2==true) recho($t);
recho(RawTransaction::encode($t));


		break;

	case "sendtoaddress":

		$params[0]=trim($params[0]);
                $p1=san($params[0]);
                if($p1!=$params[0]) recho(NULL,array("code"=>-5, "message"=>"Invalid Bitcoin address"));
                $dst_b=base58_decode($p1);
                if(strlen($dst_b)!=64)  recho(NULL,array("code"=>-5, "message"=>"Invalid Bitcoin address"));

                $p2=floatval($params[1]);
                $p3=san($params[2]," \.\-\_\,");
		$p2=number_format($p2,8,".","");		
		$message=$p3;
		if($decrypted==0) recho(NULL,array("code"=>-13,"message"=>"Enter the wallet passphrase with walletpassphrase first"));
		
		$b=getBalance("*",true);
		$fee=0.0025*$p2;
		$rfee=$fee;
		if($rfee>10) $rfee=10;
		$fee=number_format($fee,8,".","");
		if($b['balance']<$p2+0.005*$p2) recho(NULL,array("code"=>-6, "message"=>"Insufficient funds"));
		$adr=$b['addresses'];
		$tip=0;
		$total=0;
		$total_adr=array();
		$wak=0;
		foreach($adr as $x=>$l){
			$best_balance=10000000000;
			if($l==$p2+$rfee){
			//perfect match

				$from=$x;
				$tip=1;
				break;
			}elseif($l>$p2+$rfee&&$l<$best_balance){
				$tip=2;
				$best_balance=$l;
				$from=$x;		
			} else {
				if($total<$p2+0.005*$p2&&$l>0.00000001){
					$total+=$l;
					$total_adr[$x]=$l;	
					if($wak==0) $wak=$rpc->single("SELECT acc FROM wallets WHERE address=:a",array(":a"=>$x));
				}
			}
			
		}
		if($tip==1||$tip==2){
			// found a good match
			$pk=$rpc->row("SELECT * FROM wallets WHERE address=:a",array(":a"=>$from));

			openssl_private_decrypt( base64_decode($pk['private_key']), $fin, $global_priv);
			if(strlen($fin)<20) recho(NULL,array("code"=>-14, "message"=>"The wallet passphrase entered was incorrect"));
			$pk['private_key']=$fin;

			$res=pay_post("/api.php?q=send",array("dst"=>$p1,"val"=>$p2, "private_key"=>$pk['private_key'], "public_key"=>$pk['public_key'], "version"=>1, "message"=>$p3.""));
			if($res['status']!="ok"){
				recho(NULL,array("code"=>-26,"message"=>"Transaction was rejected by network rules"));
			} else {
				recho($res['data']);
			}
	
		} else {
			if(count($total_adr)<2||$total<$p2+0.005*$p2)  recho(NULL,array("code"=>-20,"message"=>"Database error"));
  			$current=$db->single("SELECT height FROM blocks ORDER by height DESC LIMIT 1");
			//no match, we need to send to a specific address
			$acc=new Account;
                	$new=$acc->generate_account();
                	if(strlen($new['private_key'])<30||strlen($new['public_key'])<30) recho(NULL,array("code"=>-20,"message"=>"Database error"));
			openssl_public_encrypt($new['private_key'], $fin, $global_pub);
 	                $newpv=base64_encode($fin);

                	$rpc->run("INSERT into wallets SET address=:address, public_key=:public_key, private_key=:private_key, data=UNIX_TIMESTAMP(), acc=:acc",
                        array(":address"=>$new['address'],":public_key"=>$new['public_key'],":private_key"=>$newpv,":acc"=>$wak));
                	$check=$rpc->single("SELECT COUNT(1) FROM wallets WHERE address=:address AND public_key=:public_key AND private_key=:private_key AND data=UNIX_TIMESTAMP() AND acc=:acc",
                        array(":address"=>$new['address'],":public_key"=>$new['public_key'],":private_key"=>$newpv,":acc"=>$wak));
                	if($check!=1) recho(NULL,array("code"=>-20,"message"=>"Database error"));
			foreach($total_adr as $x=>$l){
				$sfin=$l/1.0025;
				if($l>4000) $sfin=$l-10;
				
				 $pk=$rpc->row("SELECT * FROM wallets WHERE address=:a",array(":a"=>$x));
		                 openssl_private_decrypt( base64_decode($pk['private_key']), $fin, $global_priv);
                	         if(strlen($fin)<20) recho(NULL,array("code"=>-14, "message"=>"The wallet passphrase entered was incorrect"));
	                         $pk['private_key']=$fin;

				 $res=pay_post("/api.php?q=send",array("dst"=>$new['address'],"val"=>$sfin, "private_key"=>$pk['private_key'], "public_key"=>$pk['public_key'], "version"=>1, "message"=>"internal"));
			 	if($res['status']!="ok") recho(NULL,array("code"=>-26,"message"=>"Transaction was rejected by network rules"));
			}
			$trx=new Transaction;
			$dst=$p1;
			$fee=$rfee;
			$val=$p2;
			$val=number_format($val,8,'.','');
    			$fee=number_format($fee,8,'.','');
    			$date=time();
			$version=1;
			$message=$p3;
			$transaction=array("val"=>$val, "fee"=>$fee, "dst"=>$dst, "public_key"=>$new['public_key'],"date"=>$date, "version"=>$version,"message"=>$message);
			$signature=$trx->sign($transaction, $new['private_key']);
            		$transaction['signature']=$signature;
		   	$hash=$trx->hash($transaction);
    			$transaction['id']=$hash;
			if(!$trx->check($transaction)) recho(NULL,array("code"=>-20,"message"=>"Database error"));
			$bind=array(":height"=>$current+2, ":id"=>$hash, ":src"=>$new['address'],":fee"=>$fee, ":val"=>$val,":message"=>$message,":date"=>$date, ":public_key"=>$new['public_key'],":dst"=>$p1, ":signature"=>$signature);
			$db->run("INSERT into mempool SET height=:height, id=:id,src=:src,dst=:dst, val=:val, fee=:fee, version=1, message=:message, public_key=:public_key, date=:date, peer='local', signature=:signature",$bind);
			$res=$db->single("SELECT COUNT(1) FROM mempool WHERE id=:id",array(":id"=>$hash));

			if($res!=1) recho(NULL,array("code"=>-25,"message"=>"General error during transaction or block submission"));

			recho($hash);
		}
		break;

	case "walletpassphrase":
		$f=trim($params[0]);
		$p2=intval($params[1]);
		$global_priv=$rpc->single("SELECT val FROM wallet_config WHERE id='private_key'");
		$key=hash("sha256",getenv('GLOBAL_KEY').$f);
		$cipher = "aes-128-cbc";
		$iv=$rpc->single("SELECT val FROM wallet_config WHERE id='iv'");

		$global_priv = openssl_decrypt($global_priv, $cipher, $key, $options=0, base64_decode($iv));
		if(str_replace("-----BEGIN PRIVATE KEY-----","",$global_priv)!=$global_priv) { 
			$deadline=time()+$p2;
			$rpc->run("UPDATE wallet_config SET val=:val WHERE id='expiry'",array(":val"=>$deadline));
			file_put_contents("/etc/aro/key",$f);
			recho(NULL);
		} else recho(NULL,array("code"=>-14, "message"=>"Error: The wallet passphrase entered was incorrect."));
			
		break;
	default:
		recho(NULL,array("code"=>-32601,"message"=>"Method not found"));
		break;
}

recho($res);



?>
