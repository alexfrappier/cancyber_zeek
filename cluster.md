# Zeek Cluster Setup for CanCyber


The CanCyber Zeek module can be run in a cluster with a central manager and many workers

A worker can be a separate server with it's own capture interface, or a group of workers handling a large capture (splitting up traffic requires additional software such as PF_RING)


The CanCyber module will leverage the Zeek Intelligence Framework's transparent support for inter-cluster communications to centrally download indicators on the manager for use by all the worker nodes.


## Multiple Workers on one Server

- [Zeek Appliance Build Guide](https://github.com/cancyber/documents/pdfs/Zeek-IDS-Appliance-Build-Guide-v1.0.1.pdf)



## Multiple Servers with a Central Manager

### Setup Root SSH Keys on Servers

#### On manager:

zeek-manager# ssh-keygen 
 Generating public/private rsa key pair. 
 Enter file in which to save the key (/root/.ssh/id_rsa): [ Press Enter ] 
 Enter passphrase (empty for no passphrase): [ Press Enter ] 
 Enter same passphrase again: [ Press Enter ] 
 Your identification has been saved in /root/.ssh/id_rsa. 
 Your public key has been saved in /root/.ssh/id_rsa.pub. 

Copy public key from id_rsa.pub to the workers /root/.ssh/authorized_keys

ssh manually into each node to add to knownhosts entry.

#### Allow root to login on workers

grep Root /etc/ssh/sshd_config 
 PermitRootLogin yes

#### Restart ssh on workers

/etc/init.d/ssh restart

or

service sshd restart

### Install CanCyber module on Manager

Follow the instructions in the (readme)[README.md]


### Setup your cluster:

Note: to use a single standalone server and still use zeekctl, leave this file unchanged.

Edit /usr/local/zeek/etc/node.cfg::
[manager]
type=manager
host=10.100.1.69
 
[proxy-1]
type=proxy
host=10.100.1.69
 
[worker-1]
type=worker
host=10.100.2.249
interface=eth0
 

[worker-2]
type=worker
host=10.100.2.73
interface=eth0


[worker-3]
type=worker
host=10.100.1.71
interface=eth0


[worker-4]
type=worker
host=10.100.1.69
interface=eth0

### Deploy and Run CanCyber on workers:

/usr/local/zeek/bin/zeekctl deploy

Check status:

/usr/local/zeek/bin/zeekctl status

Stop:

/usr/local/zeek/bin/zeekctl stop

Restart / read latest signatures:

/usr/local/zeek/bin/zeekctl restart

### Viewing logs:

/usr/local/zeek/logs or /usr/local/zeek/spool


### Cron

To keep everything running and also force the reimport of content signatures:

*/5 * * * * /usr/local/zeek/bin/zeekctl cron
1 22 * * * /usr/bin/python /usr/local/zeek/share/zeek/site/canyber_zeek/update.py && /usr/local/zeek/bin/zeekctl deploy  > /dev/null 2>&1

