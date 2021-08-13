#!/usr/bin/python3

import requests
from pathlib import Path
from datetime import datetime
import email.utils as eut
import os
import hashlib
import re
import sys
import dns.zone
import dns.name
from dns.exception import DNSException
import subprocess
import textwrap

config = {
    # Blocklist download request timeout
    'req_timeout_s': 50,
    # Also block *.domain.tld
    'wildcard_block': False
}

regex_domain = '^(127|0)\\.0\\.0\\.(0|1)[\\s\\t]+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)$'
regex_domain_only = "^([a-z][a-z0-9+\-.]*://)([a-z0-9\-._~%!$&'()*+,;=]+@)?(?P<domain>([a-z0-9\-.+_~%]+|\[[a-z0-9\-._~%!$&'()*+,;=:]+\]))"
regex_no_comment = '^#.*|^$'
regex_skip_space = '^(?P<domain>.[^\s]{2,}.)$'
regex_drop_semicolon = '^(?P<domain>[^;]*)'
regex_drop_slash = "(?P<domain>[^(\/)?]*)"

lists = [
    {'url': 'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0', 'filter': regex_no_comment},
#    {'url': 'http://mirror1.malwaredomains.com/files/justdomains', 'filter': regex_no_comment},
    {'url': 'http://winhelp2002.mvps.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://adaway.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'http://someonewhocares.org/hosts/zero/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
#    {'url': 'http://www.malwaredomainlist.com/hostslist/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    # StevenBlack's list
    {'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    # Cameleon
    {'url': 'http://sysctl.org/cameleon/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    # Zeustracker
 #   {'url': 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'filter': regex_no_comment},
    # hpHosts
 #   {'url': 'https://hosts-file.net/download/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    # OpenPhish
    {'url': 'https://openphish.com/feed.txt', 'regex': regex_domain_only, 'filter': regex_no_comment},
    # CyberCrime tracker
    {'url': 'http://cybercrime-tracker.net/all.php', 'regex': regex_drop_slash, 'filter': regex_no_comment},
    # Free Ads BL from SquidBlacklist
  #  {'url': 'http://www.squidblacklist.org/downloads/dg-ads.acl', 'filter': regex_no_comment},

    # Disconnect.me
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malvertising.txt', 'regex': regex_skip_space, 'filter': regex_no_comment},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_malware.txt', 'regex': regex_skip_space,'filter': regex_no_comment},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', 'filter': regex_no_comment},
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', 'filter': regex_no_comment},

    # Tracking & Telemetry & Advertising
    {'url': 'https://v.firebog.net/hosts/Easyprivacy.txt', 'filter': regex_no_comment},
    {'url': 'https://v.firebog.net/hosts/Easylist.txt', 'filter': regex_no_comment},
    {'url': 'https://v.firebog.net/hosts/AdguardDNS.txt', 'filter': regex_no_comment},

    # Malicious list
    {'url': 'http://v.firebog.net/hosts/Shalla-mal.txt', 'filter': regex_no_comment},
    {'url': 'https://v.firebog.net/hosts/Cybercrime.txt', 'filter': regex_no_comment},
    {'url': 'https://v.firebog.net/hosts/APT1Rep.txt', 'filter': regex_no_comment},
    {'url': 'http://www.joewein.net/dl/bl/dom-bl.txt', 'regex': regex_drop_semicolon, 'filter': regex_no_comment},
    {'url': 'https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt', 'filter': regex_no_comment},

    #phishing list
    {'url': 'https://raw.githubusercontent.com/cristianmenghi/BIND-SinkHole/main/lista-negra.txt', 'regex': regex_drop_semicolon, 'filter': regex_no_comment}

]

def download_list(url):
    headers = None

    cache = Path('.cache', 'bind_adblock')
    if not cache.is_dir():
        cache.mkdir(parents=True)
    cache = Path(cache, hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.utcfromtimestamp(cache.stat().st_mtime)
        headers = {
                'If-modified-since': eut.format_datetime(last_modified),
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'
                }

    try:
        r = requests.get(url, headers=headers, timeout=config['req_timeout_s'])

        if r.status_code == 200:
            with cache.open('w') as f:
                f.write(r.text)

            if 'last-modified' in r.headers:
                last_modified = eut.parsedate_to_datetime(r.headers['last-modified']).timestamp()
                os.utime(str(cache), times=(last_modified, last_modified))

            return r.text
        elif r.status_code != 304:
            print("Error getting list at " + url + " HTTP STATUS:" + str(r.status_code))
    except requests.exceptions.RequestException as e:
        print(e)

    if cache.is_file():
        with cache.open() as f:
            return f.read()

def check_domain(domain, origin):
    if domain == '':
        return False

    try:
        name = dns.name.from_text(domain, origin)
    except DNSException as e:
        return False

    return True

def parse_lists(origin):
    domains = set()
    origin_name = dns.name.from_text(origin)
    for l in lists:
        data = download_list(l['url'])
        if data:
            print(l["url"])

            lines = data.splitlines()
            print("\t{} lines".format(len(lines)))

            c = len(domains)

            for line in data.splitlines():
                domain = ''

                if 'filter' in l:
                    m = re.match(l['filter'], line)
                    if m:
                        continue

                if 'regex' in l:
                    m = re.match(l['regex'], line)
                    if m:
                        domain = m.group('domain')
                else:
                    domain = line

                domain = domain.strip()
                if check_domain(domain, origin_name):
                    domains.add(domain)

            print("\t{} domains".format(len(domains) - c))

    print("\nTotal\n\t{} domains".format(len(domains)))
    return domains

def load_zone(zonefile, origin):
    zone_text = ''
    path = Path(zonefile)

    if not path.exists():
        with path.open('w') as f:
            f.write('@ 8600 IN SOA  admin. need.to.know.only. (201702121 3600 600 86400 600 )\n@ 8600 IN NS   LOCALHOST.'.format(origin))
        print(textwrap.dedent('''\
                Zone file "{0}" created.

                Add BIND options entry:
                response-policy {{
                    zone "{1}"
                }};

                Add BIND zone entry:
                zone "{1}" {{
                    type master;
                    file "{0}";
                    allow-query {{ none; }};
                }};
        ''').format(path.resolve(), origin))


    with path.open('r') as f:
        for line in f:
            if "CNAME" in line:
                break
            zone_text += line

    return dns.zone.from_text(zone_text, origin)

def update_serial(zone):
    soa = zone.get_rdataset('@', dns.rdatatype.SOA)[0]
    soa.serial += 1

def usage(code=0):
    print('Usage: update-zonefile.py zonefile origin')
    exit(code)

if len(sys.argv) != 3:
    usage(1)

zonefile = sys.argv[1]
origin = sys.argv[2]

zone = load_zone(zonefile, origin)
update_serial(zone)

domains = parse_lists(origin)

zone.to_file(zonefile)

with Path(zonefile).open('a') as f:
    for d in (sorted(domains)):
        f.write(d + ' IN CNAME drop.sinkhole.\n')
        if config['wildcard_block']:
            f.write('*.' + d + ' IN CNAME drop.sinkhole.\n')

print("Done")
