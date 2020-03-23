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

zkg zeek package manager.

Curl is required for ActiveHTTP requests.


## Monitoring and context

The CanCyber Zeek module outputs hits to the console, logs to file, and reports hit metadata and up to 2000 bytes of a signature-hit detected session.  The CanCyber.org Zeek website is the best place to review hits and get context on the activity and actor.  Additionally, analysts are available in the Slack group to help interpret hits.


## Reporting

[CanCyber Dashboard](https://dashboard.cancyber.org/)


## Module contents:


scripts/cancyber_sigs.zeek: Module zeek-script source.

scripts/cancyber_expire.zeek: Expiration code, derived from Jan Grashoefer

signatures/cancyber_sigs.sig: Content based signatures.

__load__.zeek: Module designator.

config.zeek: Your API key goes in here.

config.zeek.orig: Clean copy of config.zeek.


zkg.meta: Zeek package manager identifier.

update.py: Python script to update signatures.

README.md: This read me file.

cluster.txt: zeekctl cluster setup for multiple servers.

zeek_install.md: Instructions for installing Zeek.

zeekctl.md: Zeekctl setup.






## Package Install

1. Install Zeek

  - Mac: brew install zeek

  - Ubuntu: apt-get install zeek

  - Centos: yum install zeek

  Configure zeek interface setting: /usr/local/etc/node.cfg

```
[zeek]
type=standalone
host=localhost
interface=en0
```

2. Install zpk (Zeek package manager):

Requirements: Python 3 and pip.

pip install zkg

3. Setup zkg:

  - zkg autoconfig

  - Edit site/local.zeek (example location /usr/local/Cellar/zeek/3.1.1/share/zeek/site/local.zeek)

    ```@load packages```

4. Install cancyber_zeek package:

  - zkg unbundle cancyber_zeek.bundle, or:

  - zkg install https://github.com/cancyber/cancyber_zeek (then edit the packages/cancyber_zeek/config.zeek to have your cancyber tool api key [not misp key]).

5. zeekctl deployment

  - zeekctl deploy (typical errors here would be missing config.zeek).

6. [Test indicators](https://cancyber.org/testing.php)

```nslookup malware-c2.com```

7. Review [CanCyber Dashboard](https://dashboard.cancyber.org/)


## Command line alternative:

If running zeek directly, reference the CanCyber folder with the signature download scripts:

sudo zeek -i en0 cancyber_zeek



## Zeekctl Maintenance

For long term monitoring, if not disabling logs as above, use zeekctl to launch, rotate logs, and restart after crashes.


### zeekctl cron jobs

*/5 * * * * /usr/local/bin/zeekctl cron

1 */12 * * * /usr/local/bin/zeekctl restart

1 1 1 * * /usr/local/bin/zkg refresh


