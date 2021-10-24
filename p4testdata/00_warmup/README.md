# Short description of P4 programs in this directory

- port-forwarding.p4 - uses a single P4 exact table to match on input port and set output port; no headers are parsed.  
- l2fwd.p4 - parses & deparses Ethernet header; uses a single P4 exact table to match on destination MAC address and set output port.
