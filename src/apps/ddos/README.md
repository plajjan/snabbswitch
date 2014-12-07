# DDoS source block App

## `DDoS` app: block sources exceeding pps/bps thresholds

The `DDoS` app implements functionality to block source hosts that exceed
certain thresholds.

Arbor, a leading DDoS mitigation system vendor, calls this functionality
"Zombie Detection" in their TMS appliance.

A number of rules are written by the operator to match traffic and calculate
pps and bps rates for matched traffic per source. Any sources exceeding the
set thresholds will be completely blocked.

For example, NTP amplification attacks are rather common these days. NTP is
normally a low rate application and by setting a threshold slightly over the
normal rate we can rather easily differentiate between legitimate hosts and
offending ones. An offending host will be completely blocked so that no traffic
from the host is allowed, it is not only NTP that is blocked.


### Operation

The DDoS app begins by determining if the packet is an IPv4 or IPv6 packet by
inspecting the ethertype field of the Ethernet header. Next the source address
is fetched and compared with a blacklist and if it's a match is is dropped.

If the source doesn't match the blacklist processing continues. The packet will
be matched against the ruleset and if a match is found the packet per second
and bits per second rates will be calculated. As soon as a source exceeds a
given threshold it will be put in the blacklist. The time a source is
blacklisted is configurable.

If the packet does not match any rules it will be forwarded and no state of
that source is held.

When an entry in the blacklist expires it is simply removed from the blacklist
and traffic from that source will again be subject to matching against the rule
set and calculation of traffic rates. If a source was in the blacklist it is
also marked as being blocked which means that once it is removed from the
blacklist it is not immediately allowed - it is merely allowed passed the first
blacklist. Traffic rates are not calculated for a source that is blacklisted so
removing it from the blacklist but keeping it in a block state means that we
can calculate the rates and make sure that the source is not exceeding any
thresholds. If a source is still exceeding thresholds it will once again be
placed in the blacklist while if it is below the thresholds it will be allowed.


### Rules

Rules are written with a BPF-style syntax which is the same as you would use
for writing a filter for tcpdump. The different rules are matched in the order
given, so take care to place rules in an order that makes sense.

A general rule rate-limiting all IPv4 traffic before having a rule that matches
IPv4 and UDP from port 123 means that the second rule will never be matched.

Similarily, make sure that rules that you expect to be hit often are before
rules that are matched less often. Performance will decrease with more rules!


### Usage

Use the following pattern to create and initialize DDoS instance


### Performance

The performancce of the `DDoS` app varies greatly based on the type of packet
and what action is chosen for that packet. It is assumed that the majority of
packets will be from source addresses that are blocked and therefore there is a
shortcut in the code for quickly blocking those source IPs.

With a simple Source -> DDoS -> Sink pipeline and the majority (>99.9%) of
traffic being blocked, the DDoS app can achieve around 10Mpps / core. This is
measured on a laptop with an i5@2.5GHz.

The parsing of packet headers is expensive and so for traffic that does not
match the blacklist, performance is typically ~1Mpps / core.

In real world, with a pipeline of 82599 NIC -> DDoS -> 82599 NIC, the observed
throughput is roughly half of the above.


## TODO
 * Do mitigation per destination IP, including different rule set per dest IP
 * Do not handle source IP address as text string. It's bits!
 * Use patricia trie instead of table for doing source IP lookups
 * Support IPv6
 * Support back-off timer in block period. E.g. start with 30 seconds, then do
   60, 120, 240 until reaches max block period
 * Calculate real pps / bps rate per source for filter matches
 * Performance: reuse datagram stuff?
 * Add lots more tests
