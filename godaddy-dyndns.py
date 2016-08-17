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
GdARecord = namedtuple("GdARecord", ["name", "ip"])


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
        return map(lambda d: GdARecord(d['name'], d['data']),
                   self._get(path).json())

    def update_A_records(self, domain, records, ip):
        path = '/domains/{}/records/A'.format(domain)
        self._put(path, list(map(lambda r: {'type': 'A',
                                              'name': r,
                                              'data': ip},
                                   records)))


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

        up_to_date, outdated = span(lambda rip: ip == rip,
                                    client.get_A_records(d.domain))

        if up_to_date != []:
            logging.info("Records %s already up to date",
                         ", ".join(map(lambda r: r.name, up_to_date)))

        if outdated != []:
            logging.info("Updating records %s",
                         ", ".join(map(lambda r: ("{} ({})"
                                                  .format(r.name, r.ip)),
                                       outdated)))
            client.update_A_records(d.domain,
                                    map(lambda r: r.name, outdated),
                                    ip)

    store_ip_as_previous_public_ip(ip)


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        logging.exception(e)
        logging.shutdown()
        sys.exit(1)
