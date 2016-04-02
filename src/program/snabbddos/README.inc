Usage:
  snabbddos [OPTIONS]

  -h, --help                Print usage information
  -m, --mconfig             Mitigation config file
  -C, --clean               Interface for clean traffic
  -D, --dirty               Interface for dirty traffic
  -V, --vlan                VLAN tag for clean traffic

Mitigate DDoS attacks fast and with style.

SnabbDDoS can be deployed in two modes; on-a-stick or with two interfaces.

The recommended deployment model is to run SnabbDDoS-on-a-stick, which means
that one physical interface is used for incoming dirty traffic as well as for
egressing clean traffic. The clean traffic is VLAN tagged to separate it from
the dirty ingress traffic.

It's also possible to use two physical interfaces with one for dirty ingress
traffic and a second one for egressing clean traffic.

Since traffic is unidirectional it makes sense to use the SnabbDDoS-on-a-stick
mode as it halves the number of required ports.

The interface(s) for clean and dirty traffic can be either Intel 10G cards
(based on 82599 chipset) or tap interfaces. If the specified interface is a PCI
ID to an existing 10G card the 10G driver will be used, otherwise tap
interfaces are assumed. If you wish to use tap interfaces, you need to create
the devices first:

    ip tuntap create dev dirty mode tap
    ip tuntap create dev clean mode tap
    ifconfig dirty up
    ifconfig clean up

Then you can attach tcpdump on the clean side and inject traffic to be run
through SnabbDDoS on the dirty side.

For SnabbDDoS-on-a-stick, specify the dirty interface and a vlan tag:

    snabbddos --dirty 02:00.0 --vlan 123 -m mitigations.conf

For two interfaces, specify them separately:

    snabbddos --dirty 02:00.0 --clean 02:00.1 -m mitigations.conf

SnabbDDoS will currently not respond to ARP packets so it's necessary to
configure a static ARP entry on the router on the ingress side after which
mitigation routes can be pointed to the IP address of the static ARP entry. On
the egress side the MAC address of the incoming packet is not rewritten and the
router will therefore need to have the same MAC configured as the static ARP
entry points to or it needs to be put into promiscuous mode.

The mitigation configuration file is in JSON format and lists the mitigations
that you want with rules for each mitigation. It is re-read every second and
when changes are detected the new config is loaded. Certain state loss is
associated with loading a new config which might lead to temporarily passing
packes that otherwise would have been blocked.

Example mitigations configuration file:

    {
        "192.0.2.1": {
            "rules": [
                {
                    "name": "ntp",
                    "filter": "udp and src port 123",
                    "pps_rate": 10
                }
            ]
        }
    }

The above configuration will configure one mitigation rule for the IP 192.0.2.1
where all NTP traffic will be checked to not exceed 10pps. If any source
exceeds the specified pps_rate it will be blacklisted.
