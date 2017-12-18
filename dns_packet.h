//
// Created by yzs on 12/2/17.
//

#ifndef BOOST_ASIO_DNS_DNS_PACKET_H
#define BOOST_ASIO_DNS_DNS_PACKET_H

/*
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ID |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR| Opcode |AA|TC|RD|RA| Z | RCODE |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| QDCOUNT |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ANCOUNT |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| NSCOUNT |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
| ARCOUNT |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/


// DNS header structure : 12 bytes
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1 = 1; // recursion desired
    unsigned char tc :1 = 0; // truncated message
    unsigned char aa :1 = 0; // authoritive answer
    unsigned char opcode :4 = 0; // purpose of message
    unsigned char qr :1 = 0; // query/response flag

    unsigned char rcode :4 = 0; // response code
    unsigned char cd :1 = 0; // checking disabled
    unsigned char ad :1 = 0; // authenticated data
    unsigned char z :1 = 0; // its z! reserved
    unsigned char ra :1 = 0; // recursion available

    unsigned short q_count = htons(1); // number of question entries
    unsigned short ans_count = 0; // number of answer entries
    unsigned short auth_count = 0; // number of authority entries
    unsigned short add_count = 0; // number of resource entries
};

// Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype = 1;
    unsigned short qclass = 1;
};

// Constant sized fields of the resource record structure
struct ANSWER
{
    unsigned short type = 1;
    unsigned short _class = 1;
    unsigned int ttl = 0;
    unsigned short data_len;
};

// Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

// Structure of a Query
struct QUERY
{
    unsigned char *name;
    struct QUESTION *ques;
};


// Types of DNS resource records
#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 //canonical name
#define T_SOA 6 //start of authority zone
#define T_PTR 12 //domain name pointer
#define T_MX 15 //Mail server



#endif //BOOST_ASIO_DNS_DNS_PACKET_H
