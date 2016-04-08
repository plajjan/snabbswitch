# VLAN

There are four VLAN related apps, Tagger, Untagger and VlanMux. Tagger and
Untagger are simple apps that add or remove a tag whereas VlanMux can mux and
demux packets to different interfaces based on tag.

## Tagger

Tagger adds a VLAN tag, with the configured value, to packets received on the
input interface and sends them to the output interface.

### Configuration

-  Key **tag**

*Required*. VLAN tag to add or remove from the packet


## Untagger

Untagger checks packets received on the input interface for a VLAN tag, removes
it if it matches with the configured VLAN tag and sends them to the output
interface. Packets with other VLAN tags than the configured tag will be dropped.

### Configuration

-  Key **tag**

*Required*. VLAN tag to add or remove from the packet


## VlanMux

VlanMux receives packets on the input interface named "trunk" and inspects
the ethertype and VLAN tag field of received Ethernet frames. Frames with
ethertype 0x8100 are inspected for the VLAN tag and sent out interface "vlanX"
where X is the VLAN tag parsed from the packet. If no such output interface
exists the frame is dropped. Received frames with an ethertype other than
0x8100 are sent out the output interface "native".

There is no configuration for VlanMux, simply link it to your other apps and it
will base its actions on the name of the links.
