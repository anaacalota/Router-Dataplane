Copyright 2026 Ana-Cristina Calota

# Router Dataplane Implementation

## Overview

The project represents a C implementation of a network router's dataplane,
responsible for IPv4 packet forwarding, ARP address resolution, and ICMP
control messaging.

## Project Details

### 1. IPv4 Routing & Longest Prefix Match

To optimize the packet forwarding process, I implemented a custom binary
trie data structure to achieve Longest Prefix Match (LPM):

- Each trie node represents a prefix and contains left (0) and right (1)
  child pointers.
- Routing entries are inserted bit-by-bit from the most significant bit
  (MSB) to the least significant bit (LSB), dynamically instantiating missing
  nodes.
- Specific routes with longer subnet masks naturally override general routes
  during insertion.
- The LPM lookup traverses the trie using the destination IP address bits,
  continuously updating the best matched route until no further child
  branches match. This ensures route lookup completes in $O(L)$ time
  complexity, where $L = 32$ for IPv4 addresses.

**IPv4 Handling Workflow:**

- Validates the IP header checksum and drops corrupted packets.
- Checks if the destination IP matches one of the router's local interface
  addresses; if the packet is an ICMP Echo Request, it triggers an Echo
  Reply generation.
- Checks if $TTL \le 1$ to return an ICMP Time Exceeded message, or
  decrements the TTL and recomputes the IP checksum.
- Determines the next-hop IP and outgoing interface via the LPM trie lookup.
- Resolves the next-hop MAC address using the ARP cache. If cached, it
  rewrites L2 Ethernet headers and transmits the packet; otherwise, it
  enqueues the packet and sends an ARP Request.

### 2. ARP Protocol

- **ARP Request:** When the router lacks a valid target MAC address for the
  next hop, it queues the outgoing packet and broadcasts an ARP Request
  frame ($ff:ff:ff:ff:ff:ff$) asking for the target IP's MAC address.
- **ARP Reply:** Upon receiving an ARP Reply, the router updates its ARP cache
  table and flushes all queued packets waiting for that target MAC address.
- **Target Handling:** If an incoming ARP Request targets one of the router's
  interface IPs, the router responds directly with its interface MAC
  address.

### 3. ICMP Protocol

- **ICMP Echo Request & Reply:** Responds directly with an Echo Reply (type 0)
  when receiving ping requests addressed to any of its local router interface
  IPs, swapping source/destination headers and recalculating both ICMP
  payload and IP checksums.
- **Destination Unreachable:** Generates an ICMP Destination Unreachable message
  back to the sender when no valid route exists in the routing table trie for
  the destination IP.
- **Time Exceeded:** Generates an ICMP Time Exceeded (type 11, code 0) message
  when an IP packet's TTL reaches 0 during processing.