# BIND-SinkHole / DNS Response Policy Zones

What is it?

[Wikipedia](http://en.wikipedia.org/wiki/Response_policy_zone "Wikipedia") knows.

Domain Name Service Response Policy Zones (DNS RPZ) is a method that allows a nameserver administrator to overlay custom information on top of the global DNS to provide alternate responses to queries. It is currently implemented in the ISC BIND nameserver (9.8 or later). Another generic name for the DNS RPZ functionality is "DNS firewall".

RPZ actions are evaluated before the Resolver replies back to the client.

[client] ---> [DNS Resolver]  <---> [RPZ Policies]  <---> [DNS Cache | DNS Authoritative]

#### 1
edit /etc/named.conf

#### 2 
//enable response policy zone. 
response-policy { 
    zone "rpz.local"; 
};


#### 3
and add this to named.conf

zone "rpz.local" {
    type master;
    file "rpz.local.zone";
};

#### 4 
create  rpz.local.zone

#### 5
need to conitnue the work....
