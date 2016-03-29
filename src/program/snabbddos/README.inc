Usage:
  snabbddos [OPTIONS]

  -h, --help                Print usage information
  -c, --config              Configuration file
  -C, --clean               Interface for clean traffic
  -D, --dirty               Interface for dirty traffic

Mitigate DDoS attacks fast and with style.

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
