# CanCyber Zeek Module

For [CanCyber.org](https://cancyber.org) members. The **CanCyber Foundation** provides free threat hunting capabilities to Canadian industry and their suppliers. With funding provided by the Government Canada and *Canadian Safety and Security Program* [(CSSP)](http://www.science.gc.ca/eic/site/063.nsf/eng/h_5B5BE154.html).

## Access

An API key in config.zeek is required to use this module with CanCyber.org. When you [download a package](https://endpoint.cancyber.org/tool.php) from CanCyber.org the api key should be automatically included. If you are downloading source from GitHub, add your API key to config.key.

## Not a CanCyber Member?

Request an account by getting a referral from another member or reach out for more information. You can also use [dovehawk.io](https://dovehawk.io) to connect to your own MISP instance and hunt with your own indicators in Zeek.

## Summary

This module uses the the built-in Zeek Intelligence Framework to load and monitor signatures from MISP enriched with commercial indicators and manually curated Zeek content based signatures (Zeek Signature Framework).

The script, signatures, and indicators are downloaded automatically every 6 hours.  Indicators should expire after 6.5 hours if removed from MISP.

Indicators are downloaded and read into memory automatically.  Content signatures are stored locally in `signatures/cancyber_sigs.sig` and will require a zeek restart `zeekctl restart` to take effect.

This module is based on the open source dovehawk.io module, but is enhanced to include indicators from not only the CanCyber MISP, but also over 400k+ commercial indicators. In addition this module reports sightings to a web dashboard rather than just to MISP.


## Requirements

**Zeek** 3.0 or higher.

**Python** 3 recommended

**zkg** *zeek package manager*.

**curl** is required for ActiveHTTP requests.


## Extra Documentation

This readme covers simple Zeek setup, if your traffic volume requires a Zeek Cluster (250Mb/s per CPU core) you may need additional instructions.

CanCyber general and Zeek appliance guide [Documents Repo](https://github.com/cancyber/documents)

Security Zen has a good series on installing a Zeek Cluster on Centos [part 1 - zeek](https://www.ericooi.com/zeekurity-zenpart-i-how-to-install-zeek-on-centos-8/) and [part 2 - zkg](https://www.ericooi.com/zeekurity-zen-part-ii-zeek-package-manager/).

## Video Walkthrough

[![CanCyber Zeek Install](http://img.youtube.com/vi/pbJqk049arI/0.jpg)](http://www.youtube.com/watch?v=pbJqk049arI)


## Slack Channel

[CanCyber Slack](https://cancyber.slack.com)

[Request an invite](https://cancyber.org/contact.php)


## Monitoring and Intelligence Context

The CanCyber Zeek module outputs hits to the console, logs to file, and reports hit metadata and the begining of a signature-hit detected session to the CanCyber dashboard.  The [CanCyber Dashboard](https://dashboard.cancyber.org/) is the best place to review hits and get context on the activity and actor attribution.  Additionally, analysts are available in the [Slack group](https://cancyber.slack.com) to help interpret hits.


## Web Dashboard

[CanCyber Dashboard](https://dashboard.cancyber.org/)


## Module contents:

`scripts/cancyber_sigs.zeek`: Module zeek-script source.

`scripts/cancyber_expire.zeek`: Extended functionality for the built in Intelligence Framework.

`signatures/cancyber_sigs.sig`: Content based signatures. The module self-updates this file but a zeek restart is required to load it.

`__ load __.zeek`: Module designator.

`config.zeek`: Your API key goes in here.

`config.zeek.orig`: Clean copy of config.zeek.

`zkg.meta`: Zeek package manager identifier.

`update.py`: Python script to update signatures.

`README.md`: This read me file.

`cluster.md`: zeekctl cluster setup for multiple servers.



## Package Install

Tip: You may need to be root to install and run Zeek. Prepend `sudo` to any command to run as root.

1. **Install Zeek**

See [Get Zeek](https://zeek.org/get-zeek/) for detailed instructions.

  - Mac: `brew install zeek`

  - Ubuntu: `sudo apt-get install zeek`

  - Centos: `sudo yum install zeek`

  **Configure zeek** interface setting for your system: `sudo nano /usr/local/etc/node.cfg`

```
[zeek]
type=standalone
host=localhost
interface=en0
```

  Tip: Run `ifconfig` to find the interface that currently has an IP address on your network.

2. **Install zpk** (Zeek package manager):

Requirements: [Python 3](https://realpython.com/installing-python/) and [pip](https://bootstrap.pypa.io/get-pip.py).

`sudo pip install zkg requests`

3. **Setup zkg**:

  - `sudo zkg autoconfig`

  - Edit *site/local.zeek* (example location */usr/local/Cellar/zeek/3.1.1/share/zeek/site/local.zeek*)

    `@load packages`
    
    Tip: `sudo nano /usr/local/Cellar/zeek/3.1.1/share/zeek/site/local.zeek` is a common and easy editor to edit a text file. _Control-x_, then _y_, to exit and save.

4. Get and Install cancyber_zeek.bundle package:

  From a preconfigured (API key included) install cancyber_zeek.bundle [download here](https://endpoint.cancyber.org/tool.php) - Zeek Network Module - Zeek 3+ Linux/Mac:
  
  - `sudo zkg unbundle cancyber_zeek.bundle`

```
The following packages will be INSTALLED:
https://github.com/cancyber/cancyber_zeek (master)

Proceed? [Y/n] `Y`
Loaded "https://github.com/cancyber/cancyber_zeek"
Unbundling complete. 
```

The cancyber_zeek.bundle is tar.gz compressed file pre-loaded with your API key and the most recent CanCyber content signatures. The bundle includes a manifest that tells zkg that future updates are available from github.com/cancyber/canyber_zeek


5. zeekctl deployment for always on monitoring

  - `sudo zeekctl deploy` (typical errors here would be missing *config.zeek*).
  
```
checking configurations ...
installing ...
removing old policies in /usr/local/var/spool/installed-scripts-do-not-touch/site ...
removing old policies in /usr/local/var/spool/installed-scripts-do-not-touch/auto ...
creating policy directories ...
installing site policies ...
generating standalone-layout.zeek ...
generating local-networks.zeek ...
generating zeekctl-config.zeek ...
generating zeekctl-config.sh ...
stopping ...
stopping zeek ...
starting ...
starting zeek ...
```

  
  Zeekctl will install the module and start it. See the cron section below to add the maintenance commands.


6. Test run Zeek with the cancyber_zeek module from the command line:

`sudo zeek -i en0 cancyber_zeek`

Typical errors here would be missing *config.zeek* or network errors in enterprise environments connecting to tool.cancyber.org.


```
listening on en0

Refresh period is now 6.0 hrs
Downloading CanCyber Signatures 2020/03/24 12:02:03
Cancyber Source Directory: /usr/local/Cellar/zeek/3.1.1/share/zeek/site/cancyber_zeek/./scripts/.
Downloading Indicators...
Processing Indicators...
Number of Indicators 426893
 Intel Indicator Counts:
    Intel::DOMAIN:    36275
    Intel::ADDR:        4464
    Intel::URL:        250793
    Intel::SUBNET:    0
    Intel::SOFTWARE:  10
    Intel::EMAIL:     826
    Intel::USER_NAME: 0
    Intel::FILE_HASH: 127887
    Intel::FILE_NAME: 6637
Finished Processing Indicators
```

Control-C to exit.
```
1585065905.746575 received termination signal
1585065905.746575 109231 packets received on interface en0, 8406 (7.15%) dropped
Zeek Terminating - Cancelling Scheduled Signature Downloads
```

7. Use the [Test indicators](https://cancyber.org/testing.php) to generate some sightings. These indicators and files are safe to use and download.

`nslookup malware-c2.com`

```
Server:		8.8.8.8
Address:	8.8.8.8#53

Non-authoritative answer:
Name:	malware-c2.com
Address: 35.183.9.38
```

Zeek will print a sighting and send it to CanCyber:

```
CanCyber Sighting: ZEEK|uid:C4eMxUSgTo4FzJsg4|ts:1585053181.470496|orig_h:192.168.1.90|orig_p:63181/udp|resp_h:8.8.8.8|resp_p:53/udp|msg: Intel hit on malware-c2.com at DNS::IN_REQUEST|node:zeek|d:OUTBOUND|service:DNS|orig:32|o_pkts:0|o_bytes:0|o_state:1|resp:0|r_pkts:0|r_bytes:0|r_state:0|start_time:1585053181.470496|duration:0.0|q:A
Sighting Result ===> {"result":"Hit Recorded!"}
```

8. Review test sightings online with the [CanCyber Dashboard](https://dashboard.cancyber.org/)



## Zeekctl Maintenance

Use zeekctl to launch zeek, rotate logs, and restart after crashes.


### zeekctl cron jobs

Add to or create a new cron (as root):

```
# cron regular check
*/5 * * * * /usr/local/bin/zeekctl cron

# restart to load new signatures twice daily
1 */12 * * * /usr/local/bin/zeekctl restart

# zkg update cancyber_zeek module
1 2 * 1 * /usr/local/bin/zkg upgrade --force cancyber_zeek
```

## Updates

To upgrade all installed modules to the latest version, including the CanCyber Zeek module, use zkg:

`sudo zkg upgrade cancyber_zeekk`

```
The following packages will be UPGRADED:
  https://github.com/cancyber/cancyber_zeek (master)

Proceed? [Y/n] `Y`
Upgraded "https://github.com/cancyber/cancyber_zeek" (master)
```

## Uninstall

- Stop Zeek

  `zeekctl stop`
  
- Remove package

  `zkg remove cancyber_zeek`
  
```
The following packages will be REMOVED:
  https://github.com/cancyber/cancyber_zeek

Proceed? [Y/n] **Y**
Removed "https://github.com/cancyber/cancyber_zeek"
```


## Alternate package installation directly from Github

Alternate (more complicated) installation from Github source that requires that you know your CanCyber API key.
  
  - `zkg install https://github.com/cancyber/cancyber_zeek` (then edit the *packages/cancyber_zeek/config.zeek* to have your cancyber tool api key [not misp key]). Copy a new config `cp config.zeek.orig config.zeek`.
  
```
module cancyber_zeek;

export { 

	global APIKEY = "**##APIKEY##**";

	global CCSOURCE = "zeek"; # available options zeek, isp, dev, exp
}
```

When installing from Github source you'll need an API key to add to `config.zeek`. To find your API key, go to the [tools download page](https://endpoint.cancyber.org/tool.php) and Scroll down to the **Key Revokation** section to grab a recent key. API keys are system-generated 64 digit alphanumeric sequence similar to a sha256.

