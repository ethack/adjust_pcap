# About

`adjust.py` rewrites a pcap with different timestamps based on a reference file. It is meant to make it easier to merge pcaps from different time periods. This script differs from those in [Other Resources](#other-resources) below because it will also scale timestamps. 

# Purpose

The intended use case for this script is having multiple separate pcaps and merging them together to create challenges. For instance, you can have a pcap that contains "noise" such as any publicly available large pcap. And you have another pcap from a lab environment where you recreated some specific behavior. The lab pcap is interesting to look at on its own, but by overlaying it on top of some "noise" it becomes a more realistic challenge in network traffic analysis. Generating realistic "noise" in a lab environment is a hard problem so having separate pcaps that let you re-use or swap out "noise" is beneficial.

# Details

If your reference pcap is 24 hours long and your pcap to modify is 1 hour long then your output will have the same number of packets as it did but they will be spread out over 24 hours, proportional to their original timings. This has the benefit of keeping beaconing characteristics.

This script will only scale the packet timings if the second pcap is 10% different in its time range. Otherwise, it will just shift the timings to match (which can be done just as well and probably faster with other tools).

# Usage

```
./adjust.py reference.pcap to_modify.pcap output.pcap
```

- `reference.pcap` is used for reference times. It uses the first and last timestamps to define the bounds of `to_modify.pcap`
- `to_modify.pcap` is the pcap that will have its times modified. However, this file is not modified.
- `output.pcap` is a copy of `to_modify.pcap` with all its packets' timestamps modified.

# Prerequisites

- Python3
- Scapy (not sure if the version matters)

# Other Resources

There are other tools out there that can modify pcaps.
- Wireshark's [`editcap`](https://www.wireshark.org/docs/wsug_html_chunked/AppToolseditcap.html), specifically the `-t` flag will adjust timings.
- [`tcprewrite`](https://linux.die.net/man/1/tcprewrite) can modify many fields in a pcap. Of particular interest are its capabilities of rewriting IP addresses, which could help mesh captures taken on different network subnets or allow you to give a particular host a certain behavior on top of its existing "normal" behavior.
- Wireshark's [`mergecap`](https://www.wireshark.org/docs/man-pages/mergecap.html) will do what its name implies and combine multiple pcaps into a single file.

https://tshark.dev/edit/ shows examples of `editcap` and `mergecap` in use.