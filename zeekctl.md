zeek# Zeek zeekctl setup

The CanCyber Zeek module can be installed to run automatically and restart daily to load the latest signatures.


## Install CanCyber module 

Extract zip to: /usr/local/zeek/share/zeek/site/CanCyber  
 or /usr/local/share/zeek/site/CanCyber

cp -r /Users/user/Downloads/CanCyber /usr/local/zeek/share/zeek/site/CanCyber
cp -r /Users/user/Downloads/CanCyber /usr/local/share/zeek/site/CanCyber

Edit local.zeek or local.zeek: nano -w /usr/local/zeek/share/zeek/site/local.zeek: 
nano -w /usr/local/share/zeek/site/local.zeek

add:
@load CanCyber


Test run:

/usr/local/zeek/bin/zeek -i eth0 -C
/usr/local/bin/zeek -i en0 -C

## Normal Bandwith - set interface to monitor:

Edit /usr/local/zeek/etc/node.cfg:
/usr/local/etc/node.cfg:
[zeek]
type=standalone
host=localhost
interface=eth0


## High Bandwidth Options:


Edit /usr/local/zeek/etc/node.cfg:
/usr/local/etc/node.cfg:
[manager]
type=manager
host=localhost
 
[proxy-1]
type=proxy
host=localhost
 
[worker-1]
type=worker
host=localhost
interface=eth0
 

[worker-2]
type=worker
host=localhost
interface=eth0


[worker-3]
type=worker
host=localhost
interface=eth0

etc


## Deploy and Run CanCyber on workers:

/usr/local/zeek/bin/zeekctl deploy
/usr/local/bin/zeekctl deploy

Check status:

/usr/local/zeek/bin/zeekctl status
/usr/local/bin/zeekctl status

Stop:

/usr/local/zeek/bin/zeekctl stop
/usr/local/bin/zeekctl stop

Restart / read latest signatures:

/usr/local/zeek/bin/zeekctl restart
/usr/local/bin/zeekctl restart

## Logs viewing:

/usr/local/zeek/logs or /usr/local/zeek/spool

## Cron

To keep everything running and also force the reimport of content signatures:

*/5 * * * * /usr/local/zeek/bin/zeekctl cron
1 22 * * * /usr/bin/python /usr/local/zeek/share/zeek/site/CanCyber/update.py && /usr/local/zeek/bin/zeekctl deploy  > /dev/null 2>&1

or

*/5 * * * * /usr/local/bin/zeekctl cron
1 22 * * * /usr/bin/python /usr/local/share/zeek/site/CanCyber/update.py && /usr/local/bin/zeekctl deploy  > /dev/null 2>&1


## Notes:

Each worker will individually download the signatures and report hits. Running many loads may stress the system. Please contact us if you have a high number of nodes in use.


