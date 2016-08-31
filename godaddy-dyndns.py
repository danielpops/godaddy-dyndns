#!/usr/bin/env python3

import argparse
import configparser
import ipaddress
import logging
import logging.handlers
import sys
from collections import namedtuple

import requests

PREVIOUS_IP_FILE = 'previous-ip.txt'


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
        return {d['domain']: None for d in self._get('/domains').json()}

    def get_A_records(self, domain):
        path = '/domains/{}/records/A'.format(domain)
        return self._get(path).json()

    def replace_A_records(self, domain, records):
        path = '/domains/{}/records/A'.format(domain)
        self._put(path, records)

    def replace_A_records_by_name(self, domain, record):
        path = '/domains/{}/records/A/{}'.format(domain, record['name'])
        self._put(path, [record])


class Conf:
    def __init__(self, filename):
        parser = configparser.ConfigParser()
        parser.read('godaddy-dyndns.conf')

        self.key = parser.get('godaddy', 'key')
        self.secret = parser.get('godaddy', 'secret')
        self.domains = self.__get_domains(parser)

    def __get_domains(self, parser):
        ds = {}

        for section in parser.sections():
            if section == 'godaddy':
                continue

            ds[section] = parser.get(section, 'subdomains', fallback=None)
            if ds[section] is not None:
                ds[section] = set(map(str.strip, ds[section].split(',')))

        if ds == {}:
            return None
        else:
            return ds


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


def get_public_ip_if_changed(debug):
    current_public_ip = get_public_ip()

    if debug:
        return current_public_ip

    previous_public_ip = get_previous_public_ip()

    if current_public_ip != previous_public_ip:
        return current_public_ip
    else:
        return None


def init_logging(debug):
    l = logging.getLogger()
    l.setLevel(logging.INFO)

    if debug:
        l.addHandler(logging.StreamHandler())
    else:
        rotater = logging.handlers.RotatingFileHandler(
            'godaddy-dyndns.log', maxBytes=10000000, backupCount=2)
        l.addHandler(rotater)
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


def main(args):
    init_logging(args.debug)

    ip = get_public_ip_if_changed(args.debug)

    # If the IP hasn't changed then there's nothing to do.
    if ip is None:
        return 0

    conf = Conf('godaddy-dyndns.conf')
    client = GdClient(conf.key, conf.secret)

    logging.info("New IP %s", ip)

    domains = client.get_domains() if conf.domains is None else conf.domains
    for d, sds in domains.items():
        logging.info("Checking %s", d)

        records = client.get_A_records(d)

        if sds is None:
            relevant_records = records
        else:
            relevant_records = list(filter(lambda r: r['name'] in sds, records))
            non_existing = sds - set(map(lambda r: r['name'], relevant_records))
            if non_existing != set():
                logging.warning('Subdomains %s do not exist', ', '.join(non_existing))

        if not all_unique(map(lambda r: r['name'], relevant_records)):
            logging.error('Aborting: All records must have unique names. '
                          'Cannot update without losing information (e.g. TTL)'
                          '. Make sure all records have unique names before '
                          're-run the script.')
            return 1

        up_to_date, outdated = span(lambda r: ip == r['data'], relevant_records)

        if up_to_date != []:
            logging.info("Records %s already up to date",
                         ", ".join(map(lambda r: r['name'], up_to_date)))

        if outdated != []:
            if sds is None:
                # This replaces all records so we need to include
                # non-relevant and non-outdated also
                logging.info("Updating records %s",
                             ", ".join(map(lambda r: ("{} ({})"
                                                      .format(r['name'],
                                                              r['data'])),
                                           outdated)))

                for r in outdated:
                    r['data'] = ip

                client.replace_A_records(d, records)
            else:
                # In case we do not update all A records we cannot
                # assume that we are the only writer for this
                # domain. So we cannot safely overwrite everything (as
                # that might overwrite what other writers have
                # written) in one request.
                for r in outdated:
                    logging.info("Updating record %s (%s)", r['name'], r['data'])
                    r['data'] = ip
                    client.replace_A_records_by_name(d, r)

    store_ip_as_previous_public_ip(ip)
    return 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()

    try:
        sys.exit(main(args))
    except Exception as e:
        logging.exception(e)
        logging.shutdown()
        sys.exit(1)
