// Windows-compatible PCAP router integrated with routing simulation

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>

#include <windows.h> // timing from window api


#define MAX_ROUTES 100
#define MAX_NEIGHBORS 10
#define MAX_LINE 100
#define MAX_INTERFACES 10
#define ETHER_ADDR_LEN 6

#pragma comment(lib, "Ws2_32.lib")

typedef struct Device Device;

typedef struct {
    char name[16];
    char ip_addr[32];
} Interface;

typedef struct {
    char network[32];
    int prefix_len;
    Interface* netif;
} RoutingEntry;

typedef struct {
    Interface* iface;
    Device* neighbor;
} Neighbor;

struct Device {
    char name[16];
    RoutingEntry routes[MAX_ROUTES];
    int route_count;

    Interface interfaces[MAX_INTERFACES];
    int iface_count;

    char owned_subnets[MAX_ROUTES][32];
    int owned_count;

    Neighbor neighbors[MAX_NEIGHBORS];
    int neighbor_count;

    FILE* pcap_out;

    int packet_received;
    int packet_written;
};

uint32_t ip_to_uint(const char* ip_str) {
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    return ntohl(addr.S_un.S_addr);
}

int prefix_match(uint32_t ip, uint32_t net, int prefix_len) {
    uint32_t mask = prefix_len == 0 ? 0 : 0xFFFFFFFF << (32 - prefix_len);
    return (ip & mask) == (net & mask);
}

void init_device(Device* dev, const char* name, const char* pcap_filename) {
    typedef struct {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        uint32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } PcapGlobalHeader;

    strcpy(dev->name, name);
    dev->route_count = 0;
    dev->iface_count = 0;
    dev->neighbor_count = 0;
    dev->owned_count = 0;
    dev->pcap_out = fopen(pcap_filename, "wb");
    if (!dev->pcap_out) {
        printf("Failed to open pcap output for device %s\n", name);
        return;
    }

    dev->packet_received = 0;
    dev->packet_written = 0;


    // simulate tcpdump header for wireshark compatibility
    PcapGlobalHeader hdr = { 
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1
    };
    fwrite(&hdr, sizeof(hdr), 1, dev->pcap_out);
}

void load_routes(Device* dev, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    char line[MAX_LINE];
    int iface_id = 0;
    while (fgets(line, sizeof(line), f)) {
        char* net = strtok(line, "/\n");
        char* prefix = strtok(NULL, "/\n");
        if (!net || !prefix) continue;
        RoutingEntry* entry = &dev->routes[dev->route_count++];
        strcpy(entry->network, net);
        entry->prefix_len = atoi(prefix);
        if (iface_id < dev->iface_count) {
            entry->netif = &dev->interfaces[iface_id++];
        }
    }
    fclose(f);
}

void load_owned(Device* dev, const char* filename) {
    FILE* f = fopen(filename, "r");
    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        strtok(line, "\n");
        strcpy(dev->owned_subnets[dev->owned_count++], line);
    }
    fclose(f);
}

void add_interface(Device* dev, const char* name, const char* ip) {
    if (dev->iface_count >= MAX_INTERFACES) return;
    Interface* iface = &dev->interfaces[dev->iface_count++];
    strcpy(iface->name, name);
    strcpy(iface->ip_addr, ip);
}

void add_neighbor(Device* dev, const char* iface_name, Device* neighbor_dev) {
    for (int i = 0; i < dev->iface_count; i++) {
        if (strcmp(dev->interfaces[i].name, iface_name) == 0) {
            Neighbor* n = &dev->neighbors[dev->neighbor_count++];
            n->iface = &dev->interfaces[i];
            n->neighbor = neighbor_dev;
            return;
        }
    }
}

int owns_address(Device* dev, const char* ip) {
    uint32_t ip_num = ip_to_uint(ip);
    for (int i = 0; i < dev->owned_count; i++) {
        char subnet_copy[32];
        strcpy(subnet_copy, dev->owned_subnets[i]);
        char* token = strtok(subnet_copy, "/");
        char* prefix = strtok(NULL, "/");
        if (!token || !prefix) continue;
        uint32_t net_num = ip_to_uint(token);
        int prefix_len = atoi(prefix);
        if (prefix_match(ip_num, net_num, prefix_len)) return 1;
    }
    return 0;
}

void forward_packet(Device* dev, const char* src_ip, const char* dst_ip, const uint8_t* full_pkt, size_t pkt_size) {
    //printf("[%s] Packet from %s to %s\n", dev->name, src_ip, dst_ip);
    dev->packet_received++;

    if (owns_address(dev, dst_ip)) {
        //printf("[%s] Packet reached destination. Writing to PCAP.\n", dev->name);
        if (dev->pcap_out)
            fwrite(full_pkt, 1, pkt_size, dev->pcap_out);
        dev->packet_written++;
        return;
    }

    uint32_t dst = ip_to_uint(dst_ip);
    for (int i = 0; i < dev->route_count; i++) {
        uint32_t net = ip_to_uint(dev->routes[i].network);
        if (prefix_match(dst, net, dev->routes[i].prefix_len)) {
            Interface* out_iface = dev->routes[i].netif;
            for (int j = 0; j < dev->neighbor_count; j++) {
                if (dev->neighbors[j].iface == out_iface) {
                    //printf("[%s] Forwarding to %s\n", dev->name, dev->neighbors[j].neighbor->name);
                    forward_packet(dev->neighbors[j].neighbor, src_ip, dst_ip, full_pkt, pkt_size);
                    return;
                }
            }
            printf("[%s] No neighbor connected on %s\n", dev->name, out_iface->name);
            return;
        }
    }

    printf("[%s] Dropped: No route to %s\n", dev->name, dst_ip);
}

void process_pcap(const char* input_pcap, Device* input_dev) {
    typedef struct {
        uint32_t magic;
        uint16_t ver_major;
        uint16_t ver_minor;
        uint32_t thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } PcapHeader;

    typedef struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    } PacketHeader;

    FILE* f = fopen(input_pcap, "rb");
    if (!f) { printf("Failed to open PCAP\n"); return; }

    PcapHeader pcap_hdr;
    fread(&pcap_hdr, sizeof(pcap_hdr), 1, f);

    // Begin timing
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    int packet_count = 0;

    while (!feof(f)) {
        PacketHeader pkt_hdr;
        if (fread(&pkt_hdr, sizeof(pkt_hdr), 1, f) != 1) break;

        uint8_t buffer[2048];
        if (pkt_hdr.incl_len > sizeof(buffer)) break;
        fread(buffer, 1, pkt_hdr.incl_len, f);

        if (pkt_hdr.incl_len < 34) continue;
        char src_ip[32], dst_ip[32];
        sprintf(src_ip, "%u.%u.%u.%u", buffer[26], buffer[27], buffer[28], buffer[29]);
        sprintf(dst_ip, "%u.%u.%u.%u", buffer[30], buffer[31], buffer[32], buffer[33]);

        uint8_t full_packet[4096];
        memcpy(full_packet, &pkt_hdr, sizeof(pkt_hdr));
        memcpy(full_packet + sizeof(pkt_hdr), buffer, pkt_hdr.incl_len);

        forward_packet(input_dev, src_ip, dst_ip, full_packet, sizeof(pkt_hdr) + pkt_hdr.incl_len);
        packet_count++;
    }

    // End timing
    QueryPerformanceCounter(&end);

    double elapsed_seconds = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    printf("\nProcessed %d packets in %.6f seconds\n", packet_count, elapsed_seconds);

    fclose(f);
}

void show_stats(Device* dev, double total_seconds) {
    printf("\n--- Stats for %s ---\n", dev->name);
    printf("Packets received: %d\n", dev->packet_received);
    printf("Packets written to .pcap (reached destination): %d\n", dev->packet_written);
    printf("Pps (Packets per second): %.2f Pps\n", dev->packet_received / total_seconds);
}

void forward_packet_no_pcap(Device* dev, const char* src_ip, const char* dst_ip) {
    printf("[%s] Packet from %s to %s\n", dev->name, src_ip, dst_ip);
    dev->packet_received++;

    if (owns_address(dev, dst_ip)) {
        printf("[%s] Packet reached destination. \n", dev->name);
        return;
    }

    uint32_t dst = ip_to_uint(dst_ip);
    for (int i = 0; i < dev->route_count; i++) {
        uint32_t net = ip_to_uint(dev->routes[i].network);
        if (prefix_match(dst, net, dev->routes[i].prefix_len)) {
            Interface* out_iface = dev->routes[i].netif;
            for (int j = 0; j < dev->neighbor_count; j++) {
                if (dev->neighbors[j].iface == out_iface) {
                    printf("[%s] Forwarding to %s\n", dev->name, dev->neighbors[j].neighbor->name);
                    forward_packet_no_pcap(dev->neighbors[j].neighbor, src_ip, dst_ip);
                    return;
                }
            }
            printf("[%s] No neighbor connected on %s\n", dev->name, out_iface->name);
            return;
        }
    }

    printf("[%s] Dropped: No route to %s\n", dev->name, dst_ip);
}


int main() {

    char inPcap[30];

    
    printf("Enter Packet File: ");
    scanf("%s", inPcap);
    
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    Device A, B, C, D;
    init_device(&A, "Juniper", "./pcap_device/juniper_out.pcap");
    init_device(&B, "Cisco", "./pcap_device/cisco_out.pcap");
    init_device(&C, "Satellite", "./pcap_device/satellite_out.pcap");
    init_device(&D, "Internet", "./pcap_device/internet_out.pcap");

    add_interface(&A, "eth0", "192.168.1.1");
    add_interface(&A, "eth1", "192.168.2.1");
    add_interface(&A, "eth2", "192.168.5.1");  

    add_interface(&B, "eth0", "192.168.1.2");
    add_interface(&C, "eth0", "192.168.2.2");
    add_interface(&D, "eth0", "192.168.5.2");

    add_neighbor(&A, "eth0", &B);
    add_neighbor(&A, "eth1", &C);
    add_neighbor(&A, "eth2", &D);  

    add_neighbor(&B, "eth0", &A);
    add_neighbor(&C, "eth0", &A);
    add_neighbor(&D, "eth0", &A);  

    load_routes(&A, "./routes_device/routes_A.txt");
    load_routes(&B, "./routes_device/routes_B.txt");
    load_routes(&C, "./routes_device/routes_C.txt");
    load_routes(&D, "./routes_device/routes_D.txt");  

    load_owned(&B, "./owned_device/owned_B.txt");
    load_owned(&C, "./owned_device/owned_C.txt");
    load_owned(&D, "./owned_device/owned_D.txt");  


  

    printf("\n=== Processing pcap ===\n");

    //debug test
    /*
    forward_packet_no_pcap(&A, "166.0.1.1", "164.8.8.8");
    forward_packet_no_pcap(&A, "166.0.1.1", "214.8.8.8");
    forward_packet_no_pcap(&A, "166.0.1.1", "8.8.8.8");
    forward_packet_no_pcap(&A, "197.0.1.1", "148.8.8.8");
    */
    process_pcap(inPcap, &A);

    QueryPerformanceCounter(&end);
    double total_seconds = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;

    show_stats(&A, total_seconds);
    show_stats(&B, total_seconds);
    show_stats(&C, total_seconds);

    show_stats(&D, total_seconds);


    fclose(A.pcap_out);
    fclose(B.pcap_out);
    fclose(C.pcap_out);
    fclose(D.pcap_out);



    return 0;
}