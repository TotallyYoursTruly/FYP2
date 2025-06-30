    #define NULL 0
    #define TCPDUMP_MAGIC 0xa1b2c3d4
    #define VERSION_MAJOR 2
    #define VERSION_MINOR 4

    #define DLT_NULL 0
    #define DLT_ETH100MB 1
    #define DLT_ETH3MB 2

    //Ethernet header
    #define ETHER_ADDR_LEN 6
    #include <stdio.h>
    #include <fstream>
    #include <iostream>
    #include <string>
    #include <chrono>
    #include <cstdlib>

    using namespace std;



    struct tcpdump_hdr // when capture packet with tcpdump, will got its header first in the file
    {
        unsigned int magic;
        unsigned short ver_major;
        unsigned short ver_minor;
        unsigned int this_timezone;
        unsigned int sigfigs;
        unsigned int snaplen;
        unsigned int dlt_type; 
    };

    struct packet_hdr // packet header
    {
        unsigned int tstamp_sec;
        unsigned int tstamp_usec;
        unsigned int caplen;
        unsigned int len;
    };
    
    struct eth_hdr // ethernet header (header of ethernet frame that encapsulates payload)
    {
        unsigned char dest_addr[ETHER_ADDR_LEN];
        unsigned char src_addr[ETHER_ADDR_LEN];
        unsigned short eth_protocol;   // 0x0800 ipv4, 0x806 arp, 0x86dd ipv6
        // supposed to have crc checksum, but usually got removed by hardware
    };

    void appendCIDR(int cidr, const string& ifilename, const string& ofilename) {
        
        ifstream infile(ifilename);
        ofstream outfile(ofilename);

        if (!infile || !outfile)
        {
           cerr << "error opening file" << (infile ? ofilename : ifilename) << endl;
           return;
        }
        
        string line;
        while (getline(infile, line))
        {
            if (!line.empty())
            {
                outfile << line << "/" << cidr << endl;
            }
                 
        }

        infile.close();
        outfile.close();

        cout << "\ncidr /" << cidr << "appended! " << endl;
        
    }

    
    int main(int argc, char *argv[]) {

        unsigned int remain_len = 0;
        unsigned char temp=0, hlen, version, tlen;
        int i,count = 0;

        tcpdump_hdr tcphdr;
        packet_hdr phdr;
        eth_hdr ehdr;
        unsigned char buff, array[1500];
        
        chrono::duration<double> pcap_elapsed;


        char inPcap[100];

        cout << ".pcap Cleanify" << endl;
        cout << "enter the name of the input file?  ";
        cin >> inPcap; 


       
        FILE* pcapin = fopen(inPcap,"rb");
        FILE* pcapout = fopen("Junyper2Cisco.pcap", "wb");
        FILE* pcapout2 = fopen("Cisco2Junyper.pcap", "wb");

        FILE* list_ip = fopen("ip_list_J2C.txt", "w");
        FILE* list_ip2 = fopen("ip_list_C2J.txt", "w");

        

        if(pcapin == NULL) {
            cerr << "error opening pcap file" << endl;
            return 1;
        }
        else
        {  
            auto pcap_start = chrono::high_resolution_clock::now();

            fread((char*)&tcphdr, sizeof(tcphdr), 1, pcapin);
            fwrite(&tcphdr, sizeof(tcphdr), 1, pcapout);
            fwrite(&tcphdr, sizeof(tcphdr), 1, pcapout2);

            cout << "size of tcphdr: " << sizeof(tcphdr) << endl;
            cout << "\n*************************Packet Header*************************" << endl;
            cout << "TCPDUMP MAGIC NUM: " << tcphdr.magic << endl;
            cout << "MAJOR VER: " << tcphdr.ver_major << endl;
            cout << "MINOR VER: " << tcphdr.ver_minor << endl;
            cout << "GMT to Local timezone correction: " << tcphdr.this_timezone << endl;
            cout << "Accuracy to Timestamp: " << tcphdr.sigfigs << endl;
            cout << "Jacked Packet with LENGTH OF: " << tcphdr.snaplen << endl;
            cout << "Data Link Type (Ethernet Type II = 1): " << tcphdr.dlt_type << endl;

            cout<< "\n.\n.\n.\n creating file..."; 

            

            while (fread((char*)&phdr, sizeof(phdr), 1, pcapin))
            {


                fread((char*)&ehdr, sizeof(ehdr), 1, pcapin);

                for (i = 0; i < phdr.caplen-14; i++)
                {
                    fread((char*)&buff, sizeof(buff), 1, pcapin);
                                //printf(" %x", buff);
                                array[i] = buff;
                }

                /*cisco 00:0e:39:e3:34:00 & Juniper 00:90:69:ec:ad:5c*/
                
                // Junyper2Cisco
                if ( (((int) ehdr.src_addr[0] == 0x00) && ((int) ehdr.src_addr[1] == 0x90) && ((int) ehdr.src_addr[2] == 0x69 && ((int) ehdr.src_addr[3] == 0xec)) && ((int) ehdr.src_addr[4] == 0xad) && ((int) ehdr.src_addr[5] == 0x5c)) 
                 && (((int) ehdr.dest_addr[0] == 0x00) && ((int) ehdr.dest_addr[1] == 0x0e) && ((int) ehdr.dest_addr[2] == 0x39 && ((int) ehdr.dest_addr[3] == 0xe3)) && ((int) ehdr.dest_addr[4] == 0x34) && ((int) ehdr.dest_addr[5] == 0x00)) 
                && (ehdr.eth_protocol == 8) )
                {
                    fwrite(&phdr, sizeof(phdr), 1, pcapout);

                    fwrite(&ehdr, sizeof(ehdr), 1, pcapout);

                    fprintf(list_ip, "%d.%d.%d.%d\n", array[16], array[17], array[18], array[19]); // write src Junyper ip address to .txt file

                    for (i = 0; i < phdr.caplen-14; i++)
                    {
                        fwrite(&array[i], sizeof(unsigned char), 1, pcapout);
                    }
                    
                }
                
                // Cisco2Junyper
                else if ( (((int) ehdr.src_addr[0] == 0x00) && ((int) ehdr.src_addr[1] == 0x0e) && ((int) ehdr.src_addr[2] == 0x39 && ((int) ehdr.src_addr[3] == 0xe3)) && ((int) ehdr.src_addr[4] == 0x34) && ((int) ehdr.src_addr[5] == 0x00))
                 && (((int) ehdr.dest_addr[0] == 0x00) && ((int) ehdr.dest_addr[1] == 0x90) && ((int) ehdr.dest_addr[2] == 0x69 && ((int) ehdr.dest_addr[3] == 0xec)) && ((int) ehdr.dest_addr[4] == 0xad) && ((int) ehdr.dest_addr[5] == 0x5c))  
                 && (ehdr.eth_protocol == 8)  )
                {
                    fwrite(&phdr, sizeof(phdr), 1, pcapout2);

                    fwrite(&ehdr, sizeof(ehdr), 1, pcapout2);

                    fprintf(list_ip2, "%d.%d.%d.%d\n", array[16], array[17], array[18], array[19]); // write src Cisco ip address to .txt file

                    for (i = 0; i < phdr.caplen-14; i++)
                    {
                        fwrite(&array[i], sizeof(unsigned char), 1, pcapout2);
                    }
                    
                }
          
            }
            
            cout << "\n.\n.\n.\n(write file finished)";

            auto pcap_end = chrono::high_resolution_clock::now();
            pcap_elapsed = pcap_end - pcap_start;

            cout << "\nTime taken to process .pcap file: " << pcap_elapsed.count() << " seconds" << endl; 
            
        }

        fclose(pcapin);
        fclose(pcapout);
        fclose(pcapout2);

        fclose(list_ip);
        fclose(list_ip2);

        cout << "\nProcessing Text file..." << endl;
        auto txt_start = chrono::high_resolution_clock::now();

        system("sed -E \"s/([0-9]+)\\.[0-9]+\\.[0-9]+\\.[0-9]+/\\1.0.0.0/\" ip_list_J2C.txt | "
                     "sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | " 
                     "uniq > clean_ip_list_J2C.txt");

        system("sed -E \"s/([0-9]+)\\.[0-9]+\\.[0-9]+\\.[0-9]+/\\1.0.0.0/\" ip_list_C2J.txt | "
                     "sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | "
                     "uniq > clean_ip_list_C2J.txt");

        
        appendCIDR(8, "clean_ip_list_J2C.txt", "final_network_J2C.txt");
        appendCIDR(8, "clean_ip_list_C2J.txt", "final_network_C2J.txt");

        auto txt_end = chrono::high_resolution_clock::now();

        chrono::duration<double> txt_elapsed = txt_end - txt_start;
        cout << "\nTime taken to process .txt file: " << txt_elapsed.count() << " seconds" << endl;

        chrono::duration<double> total_elapsed = pcap_elapsed + txt_elapsed;
         cout << "\nTime taken to process all file: " << total_elapsed.count() << " seconds" << endl;

        return 0;
    }

