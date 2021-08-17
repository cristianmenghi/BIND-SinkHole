# BIND-SinkHole / DNS Response Policy Zones

What is it?

[Wikipedia](http://en.wikipedia.org/wiki/Response_policy_zone "Wikipedia") knows.

Domain Name Service Response Policy Zones (DNS RPZ) is a method that allows a nameserver administrator to overlay custom information on top of the global DNS to provide alternate responses to queries. It is currently implemented in the ISC BIND nameserver (9.8 or later). Another generic name for the DNS RPZ functionality is "DNS firewall".

RPZ actions are evaluated before the Resolver replies back to the client.

[client] ---> [DNS Resolver]  <---> [RPZ Policies]  <---> [DNS Cache | DNS Authoritative]

Steps:

#### 1
edit /etc/named.conf and ad points 2,3

#### 2 
```bash
//enable response policy zone. 
response-policy { 
  zone "rpz.blacklist"; 
};
```


#### 3
and add this to named.conf
```bash
zone "sinkhole." {
        type master;
        file "sinkhole.zone";
        allow-update { none; };
        allow-transfer { none; };
};
zone "rpz.blacklist" {
        type master;
        file "db.rpz.blacklist";
        allow-update { none; };
        allow-transfer { none; };
        allow-query { none; };
};
```

#### 4
create a file with called **db.rpz.blacklist** in the bind work directory, to this file we dump the updated list.

#### 5
Create a file called sinkhole.zone

```bash
$TTL 60
@            IN    SOA  sinkhole. root.sinkhole.  (
                          2021072800   ; serial
                          1h           ; refresh
                          30m          ; retry
                          1w           ; expiry
                          30m)         ; minimum
                        NS localhost.

@  IN  A  127.0.0.1
*  IN  A  127.0.0.1
@  IN  AAAA   ::1 
*  IN  AAAA   ::1
```
Now you can use a cron job to periodically get updates from diferents sources of compromised domains, and block on your DNS.

usage: update-zonefile.py [-h] [--no-bind] [--raw] [--empty] zonefile origin

for example:

`python3 update-zonefile.py /var/cache/bind/db.rpz.blacklist rpz.blacklist`

RPZ also works in the scenario to rewarite a domian, so take care of the usage of this.
