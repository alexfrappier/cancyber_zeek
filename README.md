# CanCyber Zeek Module

For CanCyber.org members. CanCyber Foundation provides free threat hunting capabilities to Canadian industry and their suppliers. With funding provided by the Government Canada and Canadian Safety and Security Program (CSSP).

## Access

An API key in config.zeek is required to use this module with CanCyber.org. Use [dovehawk.io](https://dovehawk.io) to connect to your own MISP instance.

## Summary


This modules uses the the built-in Zeek Intelligence Framework to load and monitor signatures from MISP enriched with commercial indicators and manually curated Zeek content based signatures (Zeek Signature Framework).  The module also includes a customized version of Jan Grashoefer's expiration code.

The script, signatures, and indicators are downloaded automatically every 6 hours.  Indicators should expire after 6.5 hours if removed from MISP.

Indicators are downloaded and read into memory.  Content signatures are stored locally in signatures/cancyber_sigs.sig.


## Requirements

Zeek 3.0 or higher.

Curl is required for ActiveHTTP requests.


## Monitoring and context

The CanCyber Zeek module outputs hits to the console, logs to file, and reports hit metadata and up to 2000 bytes of a signature-hit detected session.  The CanCyber.org Zeek website is the best place to review hits and get context on the activity and actor.  Additionally, analysts are available in the Slack group to help interpret hits.


## Reporting

[CanCyber Dashboard](https://dashboard.cancyber.org/)


## Module contents:

cancyber_sigs.zeek: Module zeek-script source.

cancyber_sigs.sig: Content based signatures.

cancyber_expire.zeek: Expiration code, derived from Jan Grashoefer

__load__.zeek: Module designator.

config.zeek: Your API key.

zkg.meta: Zeek package manager identifier.

update.py: Python script to download signatures (used in a cluster setup.)

README.md: This read me file.

cluster.txt: zeekctl cluster setup for multiple servers.

zeek_install.txt: Instructions for installing Zeek.


## Using CanCyber Signatures

If running zeek directly, reference the CanCyber folder with the signature download scripts:

sudo zeek -i en1 [FULL PATH]/CanCyber "Site::local_nets += { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24 }"

If running using the zeekctl interface, edit the local.zeek configuration file in /usr/local/zeek/share/zeek/site and, at the bottom, add the line:

@load [FULL PATH]/CanCyber

then run the zeekctl deploy sequence to have the scripts installed.


## Zeek Tips

When running locally (ie running zeek on the same system you are generating traffic from), you may need to use the -C option to ignore checksum validation.


### Disable local logging

Add "Log::default_writer=Log::WRITER_NONE" to the command.


## Zeek Config

NOTE: Some rules make use of the global 'Site:local_nets' the variable (which defines the local networks). Its value is defined in: /usr/local/zeek/etc/networks.cfg when using zeekctl or on the command line for other uses.



### Maintenance

For long term monitoring, if not disabling logs as above, use zeekctl to launch, rotate logs, and restart after crashes.


## Zeek install

Mac: brew install zeek

Ubuntu: apt-get install zeek

Centos: yum install zeek


## zeekctl setup

edit zeekctl local config: /usr/local/share/zeek/site/local.zeek:

add: @load [FULL PATH]/CanCyber

check eth interface setting: /usr/local/etc/node.cfg

run: zeekctl deploy


## zeekctl cron jobs

*/5 * * * * /usr/local/bin/zeekctl cron

1 */12 * * * /usr/local/bin/zeekctl restart

cronjob to restart zeek to reimport signatures: 1 */4 * * * /usr/local/bin/zeekctl restart
