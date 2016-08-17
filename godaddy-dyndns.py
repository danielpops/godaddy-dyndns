#!/usr/bin/env python3

import configparser
import ipaddress
import logging
import logging.handlers
import sys
from collections import namedtuple

import requests

PREVIOUS_IP_FILE = 'previous-ip.txt'

GdDomain = namedtuple("GdDomain", ["domain", "status"])


class GdClient:
    BASE_URI = 'https://api.godaddy.com/v1'

    def __init__(self, key, secret):
        self.key = key
        self.secret = secret

    def _auth_header(self):
        return {'Authorization': 'sso-key {}:{}'.format(self.key,
                                                        self.secret)}

    def _get(self, path):
        r = requests.get(self.BASE_URI + path,
                         headers=self._auth_header())
        r.raise_for_status()
        return r

    def _put(self, path, data):
        r = requests.request('PUT',
                             self.BASE_URI + path,
                             json=data,
                             headers=self._auth_header())
        r.raise_for_status()
        return r

    def get_domains(self):
        return map(lambda d: GdDomain(d['domain'], d['status']),
                   self._get('/domains').json())

    def get_A_records(self, domain):
        path = '/domains/{}/records/A'.format(domain)
        return self._get(path).json()

    def replace_A_records(self, domain, records):
        path = '/domains/{}/records/A'.format(domain)
        self._put(path, records)

def raise_if_invalid_ip(ip):
    ipaddress.ip_address(ip)


def get_public_ip():
    r = requests.get('https://api.ipify.org')
    r.raise_for_status()

    ip = r.text
    raise_if_invalid_ip(ip)

    return ip


def get_previous_public_ip():
    try:
        with open(PREVIOUS_IP_FILE, 'r') as f:
            ip = f.read()
    except FileNotFoundError:
        return None

    # Sanity check
    raise_if_invalid_ip(ip)

    return ip


def store_ip_as_previous_public_ip(ip):
    with open(PREVIOUS_IP_FILE, 'w') as f:
        f.write(ip)


def get_public_ip_if_changed():
    current_public_ip = get_public_ip()
    previous_public_ip = get_previous_public_ip()

    if current_public_ip != previous_public_ip:
        return current_public_ip
    else:
        return None


def get_godaddy_client():
    config = configparser.ConfigParser()
    config.read('godaddy-dyndns.conf')

    return GdClient(config.get('godaddy', 'key'),
                    config.get('godaddy', 'secret'))


def init_logging():
    l = logging.getLogger()
    rotater = logging.handlers.RotatingFileHandler(
        'godaddy-dyndns.log', maxBytes=10000000, backupCount=2)
    l.addHandler(rotater)
    l.setLevel(logging.INFO)
    rotater.setFormatter(logging.Formatter('%(asctime)s %(message)s'))


def span(predicate, iterable):
    ts = []
    fs = []

    for x in iterable:
        if predicate(x):
            ts.append(x)
        else:
            fs.append(x)

    return ts, fs

def all_unique(iterable):
    seen = set()

    for x in iterable:
        if x in seen:
            return False
        seen.add(x)

    return True


def main():
    init_logging()

    ip = get_public_ip_if_changed()

    # If the IP hasn't changed then there's nothing to do.
    if ip is None:
        return None

    client = get_godaddy_client()

    logging.info("Changing all domains to %s", ip)

    for d in client.get_domains():
        logging.info("Checking %s", d.domain)

        if d.status != 'ACTIVE':
            logging.error('Expected all domains to be ACTIVE, but %s is "%s"',
                          d.domain, d.status)
            continue

        records = client.get_A_records(d.domain)

        if not all_unique(map(lambda r: r['name'], records)):
            logging.error('Aborting: All records must have unique names. Cannot'
                          ' update without losing information (e.g. TTL). '
                          'Make sure all records have unique names before '
                          're-run the script.')
            continue

        up_to_date, outdated = span(lambda r: ip == r['data'], records)

        if up_to_date != []:
            logging.info("Records %s already up to date",
                         ", ".join(map(lambda r: r['name'], up_to_date)))

        if outdated != []:
            logging.info("Updating records %s",
                         ", ".join(map(lambda r: ("{} ({})"
                                                  .format(r['name'],
                                                          r['data'])),
                                       outdated)))

            for r in outdated:
                r['data'] = ip

            # This replaces all records so we need to include non-outdated also
            client.replace_A_records(d.domain, records)

    store_ip_as_previous_public_ip(ip)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(e)
        logging.shutdown()
        sys.exit(1)
