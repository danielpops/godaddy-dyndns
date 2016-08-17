# godaddy-dyndns
DynDNS-like public IP auto-updater script for GoDaddy.

The script points all your domains and subdomains to the IP of the machine running the script.

GoDaddy's API is used; previous versions used pygodaddy (before the official API was available).

The service https://ipify.org is used to figure out the machine's public IP. The script only accesses GoDaddy when the IP has changed since its last successful invocation. It logs all its activities to `godaddy-dyndns.log` (and automatically rotates the log).

Based on [Sascha's script with the same name](https://saschpe.wordpress.com/2013/11/12/godaddy-dyndns-for-the-poor/).

## Setup

Get a (production) key and secret from https://developer.godaddy.com.

Copy `godaddy-dyndns.conf.template` to `godaddy-dyndns.conf` and add your key and secret to the new file.

Then setup a Python venv:

    python3 -m venv venv
    source venv/bin/activate
    pip install -U pip
    pip install -r requirements.txt
    deactivate

And lastly add `godaddy-dyndns.sh` to your crontab file (`crontab -e`), e.g.:

    0 * * * * /path/to/script/godaddy-dyndns.sh
    @reboot sleep 30 && /path/to/script/godaddy-dyndns.sh

The above makes sure that the script runs when your machine boots, and then every hour after that. `sleep` is used to increase the chance that the network has started before the script is run.
