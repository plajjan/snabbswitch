Usage:
  snabbddos [OPTIONS]

  -h, --help                Print usage information
  -c, --config              Configuration file
  -C, --clean               Interface for clean traffic
  -D, --dirty               Interface for dirty traffic
  -V, --vlan                VLAN tag for clean traffic

Mitigate DDoS attacks fast and with style.

The interface for clean and dirty traffic are tap interfaces. You need to
create the devices first:

    ip tuntap create dev dirty mode tap
    ip tuntap create dev clean mode tap
    ifconfig dirty up
    ifconfig clean up

Then you can attach tcpdump on the clean side and inject traffic to be run
through SnabbDDoS on the dirty side.

Clean traffic can optionally be VLAN encapsulated so that it is possible to use
the same physical interface for dirty and clean traffic but still keep
separation. Since traffic is completely unidirection through snabbddos this is
a great way to halve the number of required interfaces.

The configuration file is in JSON format and lists the mitigations that you
want with rules for each mitigation, for example:

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
