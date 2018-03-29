# json-rpc
Limited implementation for Bitcoin's JSON-RPC functions for Arionum ($ARO)

This application was developed to offer an easier way to integrate Arionum into applications which already use bitcoin.

It's an alpha release and should be treated accordinly.

Implemented functions:
walletpassphrase
getnewaddress 
getbalance
sendtoaddress
validateaddress
getrawtransaction  [only the json export should be used, the hex encoded version will not produce proper results due to differences in ARO]
listtransactions
getblockcount
getblockhash
getblock
getinfo
getnetworkinfo

It requires an Arionum Node running on the same server.

Setup instructions:
1. Create a new mysql/mariadb db/user pair
2. Install and configure the arionum node
3. Edit index.php and set the db credentials and the path to the node.
4. Import the contrib/db.sql to the DB
5. Run php index.php setup to setup the wallet
6. Create /etc/aro, set 700 permissions and chown to the http user (ex nginx)
7. Setup apache or nginx to listen on a new virtual host on the RPC port you wish and point it to the application's root.
8. Create a crontab on every minute as "php RPC-PATH/index.php cron"

You can use a bitcoin-cli client to check the functionality.
