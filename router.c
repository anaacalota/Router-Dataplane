#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define MAX_RTABLE_SIZE 100000
#define MAX_ARP_TABLE_SIZE 10000

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

struct trie_node {
    struct route_table_entry *route;
	// binary trie
    struct trie_node *child[2];
};

struct trie_node *trie_root;

struct trie_node *new_trie_node(void) {
    struct trie_node *node = calloc(1, sizeof(*node));
    DIE(node == NULL, "calloc failed");
    return node;
}

int mask_length(uint32_t mask) {
    int count = 0;
	mask = ntohl(mask);

    while (mask) {
        count += mask & 1;
        mask >>= 1;
    }
    return count;
}

void trie_insert(uint32_t prefix, uint32_t mask, struct route_table_entry *route) {
    struct trie_node *node = trie_root;
	// number of bits in the mask is the number of bits needed to traverse in the trie
    int bits = mask_length(mask);

	// traverse the trie according to the bits in the prefix, creating new nodes if necessary
    for (int i = 31; i >= 32 - bits; i--) {
		// get the i-th bit of the prefix
        int bit = (ntohl(prefix) >> i) & 1;
		// if there is no node for this bit, create one
        if (!node->child[bit]) {
            node->child[bit] = calloc(1, sizeof(struct trie_node));
			DIE(node->child[bit] == NULL, "calloc failed");
        }
		// move to the child node
        node = node->child[bit];
    }
	
    node->route = route;
}

struct route_table_entry *trie_lpm(uint32_t dest) {
    struct trie_node *node = trie_root;
    struct route_table_entry *best = NULL;
	uint32_t destination = ntohl(dest);

	// if the root has a route, it is the best match so far
    if (node && node->route) {
        best = node->route;
    }

    for (int i = 31; i >= 0 && node; i--) {
		// get the i-th bit of the destination
        int bit = (destination >> i) & 1;
		if (!node->child[bit]) {
			break;
		}
        node = node->child[bit];
        if (node && node->route) {
            best = node->route;
        }
    }

    return best;
}

// helper function to build the ethernet and ip headers
void build_ethernet_ip(char *buf, uint8_t *dest_mac, int interface, uint32_t dest_ip, size_t ip_len) {
	// fill in the ip header
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	*ip_hdr = (struct ip_hdr) {
		.ihl = 5,
		.ver = 4,
		.tos = 0,
		.tot_len = htons(sizeof(struct ip_hdr) + ip_len),
		.id = htons(4),
		.frag = 0,
		.ttl = 64,
		.proto = 1, // ICMP
		.checksum = 0,
		.source_addr = inet_addr(get_interface_ip(interface)),
		.dest_addr = dest_ip
	};

	// calculate checksum
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	// fill in the ethernet header
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	memcpy(eth_hdr->ethr_dhost, dest_mac, 6);
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(ETHERTYPE_IPV4);
}

// send an ICMP error message to the source of the packet that caused the error
void icmp_error(char *buf, size_t len, size_t interface, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hdr , uint8_t type, uint8_t code) {
	int data_len = sizeof(struct ip_hdr) + 8;
	char *reply = calloc(1, sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + data_len); // 8 bytes of data from the original packet
	DIE(reply == NULL, "calloc failed");

	struct icmp_hdr *new_icmp = (struct icmp_hdr *)(reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	char *data = reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);

	// fill in the icmp header
	*new_icmp = (struct icmp_hdr) {
		.mtype = type,
		.mcode = code,
		.un_t.echo_t.id = 0,
		.un_t.echo_t.seq = 0
	};
	memcpy(data, ip_hdr, data_len);
	new_icmp->check = 0;
	new_icmp->check = htons(checksum((uint16_t *)new_icmp, sizeof(struct icmp_hdr) + data_len));

	// fill in the ip and ethernet headers
	build_ethernet_ip(reply, eth_hdr->ethr_shost, interface, ip_hdr->source_addr, sizeof(struct icmp_hdr) + data_len);

	// send the packet
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + data_len, reply, interface);
	free(reply);
}

void icmp_echo_reply(char *buf, size_t len, size_t interface, struct ether_hdr *eth_hdr, struct ip_hdr *ip_hdr, struct icmp_hdr *icmp_hdr) {
	char *reply = calloc(1, len);
	DIE(reply == NULL, "calloc failed");

	struct icmp_hdr *new_icmp = (struct icmp_hdr *)(reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	char *data = reply + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr);

	// fill in the icmp header
	*new_icmp = (struct icmp_hdr) {
		.mtype = 0, // echo reply
		.mcode = 0,
		.un_t.echo_t.id = icmp_hdr->un_t.echo_t.id,
		.un_t.echo_t.seq = icmp_hdr->un_t.echo_t.seq
	};
	memcpy(data, buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr) - sizeof(struct icmp_hdr));
	new_icmp->check = 0;
	new_icmp->check = htons(checksum((uint16_t *)new_icmp, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr)));

	// fill in the ip and ethernet headers
	build_ethernet_ip(reply, eth_hdr->ethr_shost, interface, ip_hdr->source_addr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr));	

	// send the packet
	send_to_link(len, reply, interface);
	free(reply);
}

// structure to store packets that are waiting for an arp reply,
// so I can send them when I receive the reply
struct queued_packet {
	char *buf;
	size_t len;
	uint32_t next_hop;
	int interface;
};

// queue to store the packets that are waiting for an arp reply
static queue q;

// function that returns an entry of a given ip to the arp table
struct arp_table_entry *get_arp_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void send_arp_request (uint32_t target_ip, int interface) {
	char *buf = calloc(1, sizeof(struct ether_hdr) + sizeof(struct arp_hdr));
	DIE(buf == NULL, "calloc failed");

	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

	// fill in the arp header
	arp_hdr->hw_type = htons(1); // ethernet
	arp_hdr->proto_type = htons(ETHERTYPE_IPV4);
	arp_hdr->hw_len = 6;
	arp_hdr->proto_len = 4;
	arp_hdr->opcode = htons(1); // arp request
	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));
	for (int i = 0; i < 6; i++) {
		arp_hdr->thwa[i] = 0x00;
	}
	arp_hdr->tprotoa = target_ip;

	// fill in the ethernet header
	for (int i = 0; i < 6; i++) {
		eth_hdr->ethr_dhost[i] = 0xFF;
	}
	get_interface_mac(interface, eth_hdr->ethr_shost);
	eth_hdr->ethr_type = htons(ETHERTYPE_ARP);

	send_to_link(sizeof(*eth_hdr) + sizeof(*arp_hdr), buf, interface);
	free(buf);
}

void send_queued_packet(struct queued_packet *pack, uint8_t *destination_mac_address)
{
    struct ether_hdr *eth = (struct ether_hdr *)pack->buf;

	// rewrite the ethernet header with the destination mac address and the source mac address of the interface
	uint8_t source[6];
	get_interface_mac(pack->interface, source);
	memcpy(eth->ethr_shost, source, 6);
	memcpy(eth->ethr_dhost, destination_mac_address, 6);

	send_to_link(pack->len, pack->buf, pack->interface);
	free(pack->buf);
	pack->buf = NULL;
	free(pack);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	rtable = malloc(sizeof(struct route_table_entry) * MAX_RTABLE_SIZE);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct arp_table_entry) * MAX_ARP_TABLE_SIZE);
	DIE(arp_table == NULL, "memory");
	arp_table_len = 0;

	trie_root = new_trie_node();
	for (int i = 0; i < rtable_len; i++) {
		trie_insert(rtable[i].prefix, rtable[i].mask, &rtable[i]);
	}

	q = create_queue();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;

		if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_IPV4) {
			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

			// verify checksum
			uint16_t check = ip_hdr->checksum;
			ip_hdr->checksum = 0;

			if (check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)))) {
				continue;
			}
			ip_hdr->checksum = check;

			// see if the destination is the router
			if (ip_hdr->dest_addr == inet_addr(get_interface_ip(interface))) {
				if (ip_hdr->proto != 1) {
					continue;
				}
				struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
				if (icmp_hdr->mtype == 8) {
					icmp_echo_reply(buf, len, interface, eth_hdr, ip_hdr, icmp_hdr);
					continue;
				}
			}

			// verify and decrement ttl
			// if ttl is 0 or 1, send time exceeded
			if (ip_hdr->ttl <= 1) {
				icmp_error(buf, len, interface, eth_hdr, ip_hdr, 11, 0);
				continue;
			}

			ip_hdr->ttl--;

			struct route_table_entry *best_route = trie_lpm(ip_hdr->dest_addr);
			if (best_route == NULL) {
				icmp_error(buf, len, interface, eth_hdr, ip_hdr, 3, 0);
				continue;
			}

			uint32_t next_hop = best_route->next_hop;

			// update checksum
			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

			struct arp_table_entry *arp_entry = get_arp_entry(next_hop);
			if (arp_entry == NULL) {
				struct queued_packet *packet = malloc(sizeof(struct queued_packet));
				DIE(packet == NULL, "memory");

				packet->buf = malloc(len);
				DIE(packet->buf == NULL, "memory");

				memcpy(packet->buf, buf, len);
				packet->len = len;
				packet->next_hop = next_hop;
				packet->interface = best_route->interface;
				queue_enq(q, packet);
				send_arp_request(next_hop, best_route->interface);
				continue;
			}

			// rewrite L2 addresses
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			memcpy(eth_hdr->ethr_dhost, arp_entry->mac, 6);
			send_to_link(len, buf, best_route->interface);

		} else if (ntohs(eth_hdr->ethr_type) == ETHERTYPE_ARP) {
			struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

			// arp request
			if (ntohs(arp_hdr->opcode) == 1) {
				if (arp_hdr->tprotoa != inet_addr(get_interface_ip(interface))) {
					continue;
				}

				memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
				get_interface_mac(interface, eth_hdr->ethr_shost);
				memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
				arp_hdr->tprotoa = arp_hdr->sprotoa;
				arp_hdr->opcode = htons(2);
				get_interface_mac(interface, arp_hdr->shwa);
				arp_hdr->sprotoa = inet_addr(get_interface_ip(interface));

				send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), buf, interface);

			// arp reply
			} else if (ntohs(arp_hdr->opcode) == 2) {
				struct arp_table_entry *existing = get_arp_entry(arp_hdr->sprotoa);
				if (existing == NULL) {
                    // add new entry
                    arp_table[arp_table_len].ip = arp_hdr->sprotoa;
                    memcpy(arp_table[arp_table_len].mac, arp_hdr->shwa, 6);
                    arp_table_len++;
                } else {
                    // update existing entry
                    memcpy(existing->mac, arp_hdr->shwa, 6);
                }
				
				queue temp = create_queue();
                while (!queue_empty(q)) {
                    struct queued_packet *pack = queue_deq(q);
					// if the packet is not waiting for this arp reply, I put it in the temp queue
                    if (pack->next_hop != arp_hdr->sprotoa) {
                        queue_enq(temp, pack);
						continue;
                    }
					// the packet is waiting for this arp reply, I send it
					send_queued_packet(pack, arp_hdr->shwa);
                }
                // put back the packets that are not for this arp reply
                while (!queue_empty(temp))
                    queue_enq(q, queue_deq(temp));
            }

		} else {
			continue;
		}

	}

	return 0;
}
