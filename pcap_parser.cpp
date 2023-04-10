/*
 * Author: kayak4665664
 */
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#include <regex>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

inline void pcap_parser(pcap_t *handle, FILE *outfile);
inline void ethernet_header_parser(struct ether_header *ethernet_header,
                                   FILE *outfile);
inline void mac_address_printer(uint8_t *mac_address, FILE *outfile,
                                bool is_source);
inline void ip_header_parser(struct iphdr *ip_header, FILE *outfile);
inline void ip_tos_parser(uint8_t tos, FILE *outfile);
inline void ip_off_parser(uint16_t off, FILE *outfile);
inline void ip_protocol_parser(uint8_t ip_protocol, FILE *outfile);
inline void ip_options_parser(const u_char *packet,
                              unsigned long ip_options_length, FILE *outfile);
inline void hex_printer(const u_char *packet, unsigned long length,
                        FILE *outfile, string name);
inline void tcp_header_parser(struct tcphdr *tcp_header, FILE *outfile);
inline void tcp_th_flags_parser(uint8_t th_flags, FILE *outfile);
inline void tcp_options_parser(const u_char *packet,
                               unsigned long tcp_options_length, FILE *outfile);
inline void payload_parser(const u_char *packet, unsigned long payload_length,
                           FILE *outfile);
inline string get_payload_ascii(const u_char *packet,
                                unsigned long payload_length);
inline bool find_content_length(string http_ascii);
inline void http_body_complete(FILE *outfile);
inline void http_content_complete(FILE *outfile);
inline void reassemble_http(string payload_ascii, FILE *outfile);
inline void payload_ascii_printer(string payload_ascii, FILE *outfile,
                                  int part_count, string name);
inline void payload_ascii_filter(string payload_ascii, FILE *outfile);
inline void http_parser(string payload_ascii, FILE *outfile);
inline void tls_parser(const u_char *packet, unsigned long payload_length,
                       FILE *outfile);
inline void tls_content_type_parser(u_char content_type, FILE *outfile);
inline void tls_version_parser(u_char major, u_char minor, FILE *outfile);
inline void tls_alert_parser(const u_char *packet, int length, FILE *outfile);
inline void tls_handshake_parser(const u_char *packet, int length,
                                 FILE *outfile);
inline void tls_handshake_hello_parser(const u_char *packet, int length,
                                       FILE *outfile, bool is_server);
inline void tls_handshake_certificate_parser(const u_char *packet,
                                             FILE *outfile);

unsigned long number, http_reassembel_number, http_content_length,
    http_current_length, tls_reassembel_number, tls_current_length, tls_length,
    next_payload_buffer_length;
bool http_reassembel, tls_reassembel, is_next_payload;
string http_reassembel_message = "";
u_char next_payload_buffer[65535];

int main(int argc, char *argv[]) {
    // argv[1] is the pcap file
    if (argc != 2) {
        printf("Usage: pcap_parser <pcap file>\n");
        return -1;
    } else {
        printf("Parsing %s...\n", argv[1]);
        char errbuf[PCAP_ERRBUF_SIZE];
        auto handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1],
                    errbuf);
            return -1;
        }
        auto outfile = fopen(strcat(argv[1], ".txt"), "w");
        pcap_parser(handle, outfile);
        pcap_close(handle);
        fclose(outfile);
        printf("Parsing finished! Please check the file %s\n", argv[1]);
        return 0;
    }
}

inline void pcap_parser(pcap_t *handle, FILE *outfile) {
    struct pcap_pkthdr header;
    const u_char *packet;
    while ((packet = pcap_next(handle, &header)) != NULL) {
        fprintf(outfile, "--------------------------------------------\n");
        fprintf(outfile, "Packet number: %ld\n", ++number);
        // header information
        fprintf(outfile, "Packet length: %u\n", header.len);
        fprintf(outfile, "Bytes captured: %u\n", header.caplen);
        fprintf(outfile, "Received time: %s",
                ctime((const time_t *)&header.ts.tv_sec));
        // ethernet header 14 bytes
        auto *ethernet_header = (struct ether_header *)packet;
        if (ethernet_header == NULL) continue;
        ethernet_header_parser(ethernet_header, outfile);
        // ip header 20 bytes
        auto *ip_header =
            (struct iphdr *)(packet + sizeof(struct ether_header));
        if (ip_header == NULL) continue;
        ip_header_parser(ip_header, outfile);
        // ip options max 40 bytes
        auto ip_options_length = ip_header->ihl * 4 - sizeof(struct iphdr);
        if (ip_options_length > 0)
            ip_options_parser(
                packet + sizeof(struct ether_header) + sizeof(struct iphdr),
                ip_options_length, outfile);
        // tcp header 20 bytes
        auto *tcp_header =
            (struct tcphdr *)(packet + sizeof(struct ether_header) +
                              sizeof(struct iphdr) + ip_options_length);
        if (tcp_header == NULL) continue;
        tcp_header_parser(tcp_header, outfile);
        // tcp options max 40 bytes
        auto tcp_options_length = tcp_header->doff * 4 - sizeof(struct tcphdr);
        if (tcp_options_length > 0)
            tcp_options_parser(packet + sizeof(struct ether_header) +
                                   sizeof(struct iphdr) + ip_options_length +
                                   sizeof(struct tcphdr),
                               tcp_options_length, outfile);
        // payload
        auto payload_length = header.len - sizeof(struct ether_header) -
                              sizeof(struct iphdr) - ip_options_length -
                              sizeof(struct tcphdr) - tcp_options_length;
        if (payload_length > 0)
            payload_parser(packet + sizeof(struct ether_header) +
                               sizeof(struct iphdr) + ip_options_length +
                               sizeof(struct tcphdr) + tcp_options_length,
                           payload_length, outfile);
    }
}

inline void ethernet_header_parser(struct ether_header *ethernet_header,
                                   FILE *outfile) {
    fprintf(outfile, "+++++++++++++++++++++++++++++++++++++++++++++\n");
    mac_address_printer(ethernet_header->ether_dhost, outfile, false);
    mac_address_printer(ethernet_header->ether_shost, outfile, true);
    ethernet_header->ether_type = ntohs(ethernet_header->ether_type);
    if (ethernet_header->ether_type == ETHERTYPE_PUP)
        fprintf(outfile, "Ethernet type: 0x0200 (Xerox PUP)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_SPRITE)
        fprintf(outfile, "Ethernet type: 0x0500 (Sprite)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_IP)
        fprintf(outfile, "Ethernet type: 0x0800 (IPv4)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_ARP)
        fprintf(outfile, "Ethernet type: 0x0806 (Address Resolution)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_REVARP)
        fprintf(outfile, "Ethernet type: 0x8035 (Reverse ARP)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_AT)
        fprintf(outfile, "Ethernet type: 0x809B (AppleTalk)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_AARP)
        fprintf(outfile, "Ethernet type: 0x80F3 (AppleTalk ARP)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_VLAN)
        fprintf(outfile, "Ethernet type: 0x8100 (IEEE 802.1Q VLAN tagging)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_IPX)
        fprintf(outfile, "Ethernet type: 0x8137 (IPX)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_IPV6)
        fprintf(outfile, "Ethernet type: 0x86DD (IPv6)\n");
    else if (ethernet_header->ether_type == ETHERTYPE_LOOPBACK)
        fprintf(outfile, "Ethernet type: 0x9000 (used to test interfaces)\n");
    else
        fprintf(outfile, "Ethernet type: %04x\n", ethernet_header->ether_type);
}

inline void mac_address_printer(uint8_t *mac_address, FILE *outfile,
                                bool is_source) {
    fprintf(outfile, "%s MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
            is_source ? "Source" : "Destination", mac_address[0],
            mac_address[1], mac_address[2], mac_address[3], mac_address[4],
            mac_address[5]);
}

inline void ip_header_parser(struct iphdr *ip_header, FILE *outfile) {
    fprintf(outfile, "+++++++++++++++++++++++++++++++++++++++++++++\n");
    fprintf(outfile, "IP Version: %u\n", ip_header->version);
    fprintf(outfile, "IP Header length: %d bytes (%u)\n", ip_header->ihl * 4,
            ip_header->ihl);
    ip_tos_parser(ip_header->tos, outfile);
    fprintf(outfile, "Total length: %d\n", (ip_header->tot_len) / 256);
    ip_header->id = ntohs(ip_header->id);
    fprintf(outfile, "Identification: 0x%04x (%u)\n", ip_header->id,
            ip_header->id);
    ip_off_parser(ntohs(ip_header->frag_off), outfile);
    fprintf(outfile, "Time to live: %u\n", ip_header->ttl);
    ip_protocol_parser(ip_header->protocol, outfile);
    fprintf(outfile, "Header checksum: 0x%04x\n", ntohs(ip_header->check));
    struct in_addr addr;
    addr.s_addr = ip_header->saddr;
    fprintf(outfile, "Source IP address: %s\n", inet_ntoa(addr));
    addr.s_addr = ip_header->daddr;
    fprintf(outfile, "Destination IP address: %s\n", inet_ntoa(addr));
}

inline void ip_tos_parser(uint8_t tos, FILE *outfile) {
    fprintf(outfile, "Differentiated Services Field: 0x%02x", tos);
    fprintf(outfile, " (DSCP: CS%d, ", (tos >> 2 & 0x3f) >> 3);
    auto ecn = IPTOS_ECN(tos);
    if (ecn == IPTOS_ECN_NOT_ECT)
        fprintf(outfile, "ECN: Not-ECT)\n");
    else if (ecn == IPTOS_ECN_ECT1)
        fprintf(outfile, "ECN: ECT(1))\n");
    else if (ecn == IPTOS_ECN_ECT0)
        fprintf(outfile, "ECN: ECT(0))\n");
    else
        fprintf(outfile, "ECN: CE)\n");
}

inline void ip_off_parser(uint16_t off, FILE *outfile) {
    fprintf(outfile, "Fragment offset field: 0x%02x\n", off);
    auto flags = off & (IP_RF | IP_DF | IP_MF);
    if (flags & IP_RF) fprintf(outfile, "Flags: 0x4, Reserved, must be zero\n");
    if (flags & IP_DF) fprintf(outfile, "Flags: 0x2, Don't fragment\n");
    if (flags & IP_MF) fprintf(outfile, "Flags: 0x1, More Fragments\n");
    fprintf(outfile, "Fragment offset: %u\n", off & IP_OFFMASK);
}

inline void ip_protocol_parser(uint8_t protocol, FILE *outfile) {
    if (protocol == 0x06)
        fprintf(outfile, "Protocol: TCP (6)\n");
    else
        fprintf(outfile, "Protocol: %u\n", protocol);
}

inline void ip_options_parser(const u_char *packet,
                              unsigned long ip_options_length, FILE *outfile) {
    hex_printer(packet, ip_options_length, outfile, "IP Options");
}

inline void hex_printer(const u_char *packet, unsigned long length,
                        FILE *outfile, string name) {
    fprintf(outfile, "%s: ", name.c_str());
    for (auto i = 0; i < length; ++i) fprintf(outfile, "%02x", packet[i]);
    fprintf(outfile, "\n");
}

inline void tcp_header_parser(struct tcphdr *tcp_header, FILE *outfile) {
    fprintf(outfile, "+++++++++++++++++++++++++++++++++++++++++++++\n");
    fprintf(outfile, "TCP Source port: %u\n", ntohs(tcp_header->th_sport));
    fprintf(outfile, "TCP Destination port: %u\n", ntohs(tcp_header->th_dport));
    fprintf(outfile, "Sequence number: %u\n", ntohl(tcp_header->th_seq));
    fprintf(outfile, "Acknowledgement number: %u\n", ntohl(tcp_header->th_ack));
    fprintf(outfile, "Header length: %d bytes (%u)\n", tcp_header->th_off * 4,
            tcp_header->th_off);
    tcp_th_flags_parser(tcp_header->th_flags, outfile);
    fprintf(outfile, "Window: %u\n", ntohs(tcp_header->th_win));
    fprintf(outfile, "Checksum: 0x%04x\n", ntohs(tcp_header->th_sum));
    fprintf(outfile, "Urgent pointer: %u\n", ntohs(tcp_header->th_urp));
}

inline void tcp_th_flags_parser(uint8_t th_flags, FILE *outfile) {
    fprintf(outfile, "Flags: 0x%03x", th_flags);
    if (th_flags & TH_FIN) fprintf(outfile, " Fin");
    if (th_flags & TH_SYN) fprintf(outfile, " Syn");
    if (th_flags & TH_RST) fprintf(outfile, " Rest");
    if (th_flags & TH_PUSH) fprintf(outfile, " Push");
    if (th_flags & TH_ACK) fprintf(outfile, " Acknowlegment");
    if (th_flags & TH_URG) fprintf(outfile, " Urgent");
    fprintf(outfile, "\n");
}

inline void tcp_options_parser(const u_char *packet,
                               unsigned long tcp_options_length,
                               FILE *outfile) {
    for (auto i = 0; i < tcp_options_length;)
        if (packet[i] == TCPOPT_EOL) {
            fprintf(outfile, "TCP Option - End of Option List (EOL)\n");
            ++i;
        } else if (packet[i] == TCPOPT_NOP) {
            fprintf(outfile, "TCP Option - No-Operation (NOP)\n");
            ++i;
        } else if (packet[i] == TCPOPT_MAXSEG) {
            fprintf(outfile, "TCP Option - Maximum Segment Size (MSS)\n");
            fprintf(outfile, "Length: %u\n", TCPOLEN_MAXSEG);
            fprintf(outfile, "MSS Value: %u\n",
                    ntohs(*(uint16_t *)(packet + i + 2)));
            i += TCPOLEN_MAXSEG;
        } else if (packet[i] == TCPOPT_WINDOW) {
            fprintf(outfile, "TCP Option - Window Scale (WS)\n");
            fprintf(outfile, "Length: %u\n", TCPOLEN_WINDOW);
            fprintf(outfile, "WS Value: %u\n", packet[i + 2]);
            i += TCPOLEN_WINDOW;
        } else if (packet[i] == TCPOPT_SACK_PERMITTED) {
            fprintf(outfile, "TCP Option - SACK Permitted (SACK-P)\n");
            fprintf(outfile, "Length: %u\n", TCPOLEN_SACK_PERMITTED);
            i += TCPOLEN_SACK_PERMITTED;
        } else if (packet[i] == TCPOPT_SACK) {
            fprintf(outfile, "TCP Option - SACK\n");
            fprintf(outfile, "Length: %u\n", packet[i + 1]);
            for (auto j = 0; j < packet[i + 1] - 2; j += 8) {
                fprintf(outfile, "SACK Block %d: %u - %u\n", j / 8,
                        ntohl(*(uint32_t *)(packet + i + 2 + j)),
                        ntohl(*(uint32_t *)(packet + i + 2 + j + 4)));
            }
            i += packet[i + 1];
        } else if (packet[i] == TCPOPT_TIMESTAMP) {
            fprintf(outfile, "TCP Option - Timestamps (TS)\n");
            fprintf(outfile, "Length: %u\n", TCPOLEN_TIMESTAMP);
            fprintf(outfile, "TS Value: %u\n",
                    ntohl(*(uint32_t *)(packet + i + 2)));
            fprintf(outfile, "TS Echo Reply: %u\n",
                    ntohl(*(uint32_t *)(packet + i + 6)));
            i += TCPOLEN_TIMESTAMP;
        } else {
            fprintf(outfile, "TCP Option - Unknown\n");
            break;
        }
}

inline void payload_parser(const u_char *packet, unsigned long payload_length,
                           FILE *outfile) {
    fprintf(outfile, "+++++++++++++++++++++++++++++++++++++++++++++\n");
    // if the remaining part of previous payload is the first part of next
    // payload
    if (is_next_payload == true) {
        memcpy(next_payload_buffer + next_payload_buffer_length, packet,
               payload_length);
        packet = next_payload_buffer;
        payload_length += next_payload_buffer_length;
        is_next_payload = false;
    }
    // if not tls protocol
    if (payload_length < 5 or packet[0] < 20 and packet[0] > 26 or
        packet[1] != 0x03 or packet[2] < 0x01 and packet[2] > 0x04) {
        string payload_ascii = get_payload_ascii(packet, payload_length);
        // reassembel http message
        if (http_reassembel) {
            http_reassembel_message += payload_ascii;
            // if http header is incomplete
            if (payload_ascii.find("\r\n\r\n") != string::npos) {
                // if Content-Length is found
                if (find_content_length(http_reassembel_message))
                    http_content_complete(outfile);
                else
                    http_body_complete(outfile);
            } else if (http_content_length == 0)
                fprintf(outfile, "Protocol: HTTP (Reassembel)\n");
            else {
                http_current_length = http_reassembel_message.length() -
                                      http_reassembel_message.find("\r\n\r\n") -
                                      4;
                http_content_complete(outfile);
            }
        } else if (payload_ascii.find("HTTP/0.9") != string::npos or
                   payload_ascii.find("HTTP/1.0") != string::npos or
                   payload_ascii.find("HTTP/1.1") != string::npos or
                   payload_ascii.find("HTTP/2.0") != string::npos or
                   payload_ascii.find("HTTP/3.0") != string::npos) {
            // if http header is complete
            if (payload_ascii.find("\r\n\r\n") != string::npos) {
                // if Content-Length is found
                if (find_content_length(payload_ascii)) {
                    if (http_content_length > http_current_length)
                        reassemble_http(payload_ascii, outfile);
                    else {
                        // http body is complete
                        fprintf(outfile, "Protocol: HTTP\n");
                        http_parser(payload_ascii, outfile);
                        http_content_length = 0;
                    }
                } else {
                    // no Content-Length
                    fprintf(outfile, "Protocol: HTTP\n");
                    http_parser(payload_ascii, outfile);
                }
            } else
                reassemble_http(payload_ascii, outfile);
        } else if (tls_reassembel == true) {
            // reassmble tls message
            tls_current_length += payload_length;
            fprintf(outfile, "Protocol: TLS Reassembel (%ld - %ld)\n",
                    tls_reassembel_number, number);
            // tls message is complete
            if (tls_current_length >= tls_length) {
                tls_reassembel = false;
                // if there is remaining data
                if (tls_current_length > tls_length) {
                    next_payload_buffer_length =
                        tls_current_length - tls_length;
                    is_next_payload = true;
                    memcpy(next_payload_buffer,
                           packet + payload_length - next_payload_buffer_length,
                           next_payload_buffer_length);
                }
            }
        } else {
            // other protocol
            payload_ascii_filter(payload_ascii, outfile);
            payload_ascii_printer(payload_ascii, outfile, 80, "Payload ASCII");
        }
    } else
        tls_parser(packet, payload_length, outfile);
}

inline string get_payload_ascii(const u_char *packet,
                                unsigned long payload_length) {
    string payload_ascii = "";
    for (auto i = 0; i < payload_length; ++i) payload_ascii += packet[i];
    return payload_ascii;
}

inline bool find_content_length(string http_ascii) {
    regex http_content_length_regex("Content-Length: (\\d+)");
    smatch http_content_length_match;
    // if Content-Length is found
    if (regex_search(http_ascii, http_content_length_match,
                     http_content_length_regex)) {
        // set content length and current length
        http_content_length = stoi(http_content_length_match[1]);
        http_current_length =
            http_ascii.length() - http_ascii.find("\r\n\r\n") - 4;
        return true;
    } else
        return false;
}

inline void http_body_complete(FILE *outfile) {
    http_reassembel = false;
    fprintf(outfile, "Protocol: HTTP (Reassembel %ld - %ld)\n",
            http_reassembel_number, number);
    http_parser(http_reassembel_message, outfile);
    http_reassembel_message = "";
}

inline void http_content_complete(FILE *outfile) {
    if (http_content_length > http_current_length)
        fprintf(outfile, "Protocol: HTTP (Reassembel)\n");
    else {
        http_body_complete(outfile);
        http_content_length = 0;
    }
}

inline void reassemble_http(string payload_ascii, FILE *outfile) {
    http_reassembel_number = number;
    http_reassembel = true;
    http_reassembel_message += payload_ascii;
    fprintf(outfile, "Protocol: HTTP (Reassembel)\n");
}

inline void payload_ascii_printer(string payload_ascii, FILE *outfile,
                                  int line_count, string name) {
    fprintf(outfile, "%s:\n", name.c_str());
    auto count = 0;
    for (auto i = 0; i < payload_ascii.length(); ++i) {
        fprintf(outfile, "%c",
                isprint(payload_ascii[i]) ? payload_ascii[i] : '.');
        ++count;
        if (count == line_count) {
            fprintf(outfile, "\n");
            count = 0;
        }
    }
    if (count != 0) fprintf(outfile, "\n");
}

inline void payload_ascii_filter(string payload_ascii, FILE *outfile) {
    regex url_regex(
        "([a-zA-Z0-9_-]+(\\.[a-zA-Z0-9_-]+)*\\.([a-zA-Z]{2,6})|([0-9]{1,3}(\\.["
        "0-9]{1,3}){3}))(:[0-9]{1,4})*(/[a-zA-Z0-9\\&%_\\./-~-]*)?");
    regex mail_regex("[a-zA-Z0-9-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+");
    regex ip_regex(
        "((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?"
        "\\d\\d?)");
    smatch match;
    while (regex_search(payload_ascii, match, url_regex)) {
        fprintf(outfile, "URL: %s\n", match[0].str().c_str());
        payload_ascii = match.suffix();
    }
    while (regex_search(payload_ascii, match, mail_regex)) {
        fprintf(outfile, "Email: %s\n", match[0].str().c_str());
        payload_ascii = match.suffix();
    }
    while (regex_search(payload_ascii, match, ip_regex)) {
        fprintf(outfile, "IP: %s\n", match[0].str().c_str());
        payload_ascii = match.suffix();
    }
}

inline void http_parser(string payload_ascii, FILE *outfile) {
    // divide http message into 2 parts by \r\n\r\n
    string http_message_without_body =
               payload_ascii.substr(0, payload_ascii.find("\r\n\r\n") + 2),
           http_body = payload_ascii.substr(payload_ascii.find("\r\n\r\n") + 4),
           splits;
    // split http message without body by \r\n
    vector<string> http_message_without_body_splits;
    stringstream http_message_without_body_stringstream(
        http_message_without_body),
        start_line;
    while (getline(http_message_without_body_stringstream, splits))
        http_message_without_body_splits.push_back(splits);
    // start line
    start_line << http_message_without_body_splits[0];
    string method_or_version, uri_or_status_code, version_or_phrase;
    start_line >> method_or_version >> uri_or_status_code;
    getline(start_line, version_or_phrase);
    if (method_or_version.substr(0, 4) == "HTTP") {
        fprintf(outfile, "Response Version: %s\n", method_or_version.c_str());
        fprintf(outfile, "Status Code: %s\n", uri_or_status_code.c_str());
        fprintf(outfile, "Response Phrase: %s\n", version_or_phrase.c_str());
    } else {
        fprintf(outfile, "Request Method: %s\n", method_or_version.c_str());
        fprintf(outfile, "Request URI: %s\n", uri_or_status_code.c_str());
        fprintf(outfile, "Request Version: %s\n", version_or_phrase.c_str());
    }
    // headers
    for (auto i = http_message_without_body_splits.begin() + 1;
         i != http_message_without_body_splits.end(); ++i)
        fprintf(outfile, "%s\n", i->c_str());
    fprintf(outfile, "\\r\\n\n");
    // body
    if (http_body != "")
        payload_ascii_printer(http_body, outfile, 80, "HTTP Body");
}

inline void tls_parser(const u_char *packet, unsigned long payload_length,
                       FILE *outfile) {
    fprintf(outfile, "Protocol: TLS\n");
    auto tls_payload_length = payload_length;
    for (auto packet_index = 0; packet_index < payload_length;) {
        auto content_type = packet[packet_index];
        tls_content_type_parser(content_type, outfile);
        tls_version_parser(packet[packet_index + 1], packet[packet_index + 2],
                           outfile);
        auto length =
            (packet[packet_index + 3] << 8) + packet[packet_index + 4];
        fprintf(outfile, "Length: %d\n", length);
        packet_index += 5;
        tls_payload_length -= 5;
        if (content_type == 20) {
            fprintf(outfile, "Change Cipher Spec Message");
            if (packet[packet_index] == 1)
                fprintf(outfile, "\n");
            else
                fprintf(outfile, ": Unknown\n");
        } else if (content_type == 21) {
            fprintf(outfile, "Alert Message:\n");
            tls_alert_parser(packet + packet_index, length, outfile);
        } else if (content_type == 22) {
            fprintf(outfile, "Handshake Message:\n");
            tls_handshake_parser(packet + packet_index, length, outfile);
        } else if (content_type == 23)
            fprintf(outfile, "Encrypted Application Data\n");
        else
            fprintf(outfile, "Unknown Message\n");
        // tls message is incomplete, reassemble
        if (length > tls_payload_length) {
            tls_reassembel_number = number;
            tls_reassembel = true;
            tls_length = length;
            tls_current_length = tls_payload_length;
        }
        packet_index += length;
        tls_payload_length -= length;
    }
}

inline void tls_content_type_parser(u_char content_type, FILE *outfile) {
    if (content_type == 20)
        fprintf(outfile, "Content Type: Change Cipher Spec (20)\n");
    else if (content_type == 21)
        fprintf(outfile, "Content Type: Alert (21)\n");
    else if (content_type == 22)
        fprintf(outfile, "Content Type: Handshake (22)\n");
    else if (content_type == 23)
        fprintf(outfile, "Content Type: Application Data (23)\n");
    else if (content_type == 24)
        fprintf(outfile, "Content Type: Heartbeat (24)\n");
    else if (content_type == 25)
        fprintf(outfile, "Content Type: TLS12 Cid (25)\n");
    else if (content_type == 26)
        fprintf(outfile, "Content Type: ACK (26)\n");
    else
        fprintf(outfile, "Content Type: Unknown\n");
}

inline void tls_version_parser(u_char major, u_char minor, FILE *outfile) {
    if (major == 3) {
        if (minor == 1)
            fprintf(outfile, "Version: TLS 1.0 (0x0301)\n");
        else if (minor == 2)
            fprintf(outfile, "Version: TLS 1.1 (0x0302)\n");
        else if (minor == 3)
            fprintf(outfile, "Version: TLS 1.2 (0x0303)\n");
        else if (minor == 4)
            fprintf(outfile, "Version: TLS 1.3 (0x0304)\n");
        else
            fprintf(outfile, "Version: Unknown\n");
    } else
        fprintf(outfile, "Version: Unknown\n");
}

inline void tls_alert_parser(const u_char *packet, int length, FILE *outfile) {
    if (packet[0] == 1)
        fprintf(outfile, "Alert Type: Warning\n");
    else if (packet[0] == 2)
        fprintf(outfile, "Alert Type: Fatal\n");
    else
        fprintf(outfile, "Alert Type: Unknown\n");
    fprintf(outfile, "Alert Level: %d\n", packet[1]);
    fprintf(outfile, "Alert Description Length: %d\n", length - 2);
    hex_printer(packet + 4, length - 4, outfile, "Alert Description");
}

inline void tls_handshake_parser(const u_char *packet, int length,
                                 FILE *outfile) {
    auto handshake_type = packet[0];
    length = length - 4;
    fprintf(outfile, "Handshake Protocol: ");
    if (handshake_type == 1) {
        fprintf(outfile, "Client Hello (1)\nLength: %d\n", length);
        tls_handshake_hello_parser(packet + 4, length, outfile, false);
    } else if (handshake_type == 2) {
        fprintf(outfile, "Server Hello (2)\nLength: %d\n", length);
        tls_handshake_hello_parser(packet + 4, length, outfile, true);
    } else if (handshake_type == 11) {
        fprintf(outfile, "Certificate (11)\nLength: %d\n", length);
        tls_handshake_certificate_parser(packet + 4, outfile);
    } else if (handshake_type == 12)
        fprintf(outfile, "Server Key Exchange (12)\nLength: %d\n", length);
    else if (handshake_type == 13)
        fprintf(outfile, "Certificate Request (13)\nLength: %d\n", length);
    else if (handshake_type == 14)
        fprintf(outfile, "Server Hello Done (14)\nLength: %d\n", length);
    else if (handshake_type == 15)
        fprintf(outfile, "Certificate Verify (15)\nLength: %d\n", length);
    else if (handshake_type == 16)
        fprintf(outfile, "Client Key Exchange (16)\nLength: %d\n", length);
    else if (handshake_type == 20)
        fprintf(outfile, "Finished (20)\nLength: %d\n", length);
    else
        fprintf(outfile, "Unknown\n");
}

inline void tls_handshake_hello_parser(const u_char *packet, int length,
                                       FILE *outfile, bool is_server) {
    tls_version_parser(packet[0], packet[1], outfile);
    hex_printer(packet + 2, 32, outfile, "Random");
    auto session_id_length = packet[34];
    fprintf(outfile, "Session ID Length: %d\n", session_id_length);
    hex_printer(packet + 35, session_id_length, outfile, "Session ID");
    auto packet_cipher_suites_index = 35 + session_id_length;
    auto tls_current_length = packet_cipher_suites_index;
    if (is_server == false) {
        // client
        auto cipher_suites_length = (packet[packet_cipher_suites_index] << 8) +
                                    packet[packet_cipher_suites_index + 1];
        fprintf(outfile, "Cipher Suites Length: %d\n", cipher_suites_length);
        hex_printer(packet + packet_cipher_suites_index + 2,
                    cipher_suites_length, outfile, "Cipher Suites");
        auto packet_compression_methods_length_index =
            packet_cipher_suites_index + 2 + cipher_suites_length;
        auto compression_methods_length =
            packet[packet_compression_methods_length_index];
        fprintf(outfile, "Compression Methods Length: %d\n",
                compression_methods_length);
        hex_printer(packet + packet_compression_methods_length_index + 1,
                    compression_methods_length, outfile, "Compression Methods");
        tls_current_length +=
            2 + cipher_suites_length + 1 + compression_methods_length;
    } else {
        // server
        fprintf(outfile, "Cipher Suite: %02x%02x\n",
                packet[packet_cipher_suites_index],
                packet[packet_cipher_suites_index + 1]);
        fprintf(outfile, "Compression Method: %02x\n",
                packet[packet_cipher_suites_index + 2]);
        tls_current_length += 2 + 1;
    }
    if (length > tls_current_length) {
        auto packet_extensions_length_index = tls_current_length;
        auto extensions_length = (packet[packet_extensions_length_index] << 8) +
                                 packet[packet_extensions_length_index + 1];
        fprintf(outfile, "Extensions Length: %d\n", extensions_length);
        string extension_ascii = get_payload_ascii(
            packet + packet_extensions_length_index + 2, extensions_length);
        payload_ascii_filter(extension_ascii, outfile);
        payload_ascii_printer(extension_ascii, outfile, 80, "Extensions");
    }
}

inline void tls_handshake_certificate_parser(const u_char *packet,
                                             FILE *outfile) {
    fprintf(outfile, "Certificate Length: %d\n",
            (packet[0] << 16) + (packet[1] << 8) + packet[2]);
}