//
// async_udp_echo_server.cpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2017 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <cstdlib>
#include <iostream>
#include <boost/asio.hpp>
#include <fstream>
#include <deque>
#include <queue>
#include <iomanip>
#include "dns_packet.h"
#include <boost/chrono.hpp>

using boost::asio::ip::udp;

typedef boost::asio::ip::address_v4 ipv4_type;
typedef std::vector<ipv4_type> ip_pool;


std::ofstream loggger;

class server
{
public:
    enum Mode {
        round_robin,
        lsa
    };
    static Mode mode;

    static ip_pool servers;

    static void read_servers(const std::string &filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: failed to open " << filename << "." << std::endl;
            exit(1);
        }
        std::string s;
        while (file >> s)
            servers.push_back(ipv4_type::from_string(s));
        file.close();
        if (servers.empty()) {
            std::cerr << "Warning: empty servers list." << std::endl;
            exit(1);
        }
    }

    server(boost::asio::io_service& io_service, const ipv4_type& ip, unsigned short port)
            : socket_(io_service, udp::endpoint(ip, port))
    {
        do_receive();
    }

    void do_receive()
    {
        socket_.async_receive_from(
                boost::asio::buffer(data_, max_length), sender_endpoint_,
                [this](boost::system::error_code ec, std::size_t bytes_recvd)
                {
                    if (!ec && bytes_recvd > 0)
                    {
                        // get IP addr of the proxy and name of the queried server
                        DNS_HEADER *header = reinterpret_cast<DNS_HEADER*>(data_);
                        char* name = reinterpret_cast<char*>(data_+ sizeof(DNS_HEADER));
                        int name_len = 0;
                        while(name[name_len] != 0)
                            name_len += name[name_len] + 1;
                        name_len++;  // include the last '\0'

                        if (std::strcmp(name, "\005video\003pku\003edu\002cn") == 0) {
                            ipv4_type ans_ip = get_server(sender_endpoint_.address().to_v4());
                            std::string hostname(name);
                            for (std::string::iterator i = hostname.begin(); i != hostname.end(); ) {
                                uint8_t next = (uint8_t)(*i);
                                *i = '.';
                                i += next + 1;
                            }
                            header->qr = 1;
                            header->aa = 1;
                            header->tc = 0;
                            header->rd = 0;
                            header->ra = 0;
                            header->z = 0;
                            header->rcode = 0;
                            header->q_count = ntohs(1);
                            header->ans_count = ntohs(1);
                            header->auth_count = 0;
                            header->add_count = 0;
                            uint16_t *rname = reinterpret_cast<uint16_t*>(data_ + sizeof(DNS_HEADER) + name_len + sizeof(QUESTION));
                            *rname = htons(0xC00C);
                            ANSWER *ans = (ANSWER*)(rname + 1);
                            ans->type = htons(1);
                            ans->_class = htons(1);
                            ans->ttl = htonl(0);
                            ans->data_len = htons(sizeof(uint32_t)); // length of 32bit
                            uint32_t *ip = reinterpret_cast<uint32_t*>(ans+1);
                            std::memcpy(ip, ans_ip.to_bytes()._M_elems, sizeof(uint32_t));
                            //std::cout << uint32_t(*ip) << std::endl;
                            //uint8_t *addition = reinterpret_cast<uint8_t *>(ip+1);
                            //std::memcpy(addition, "\000\000\224\360\005\000\000\000\000\000\000", 11);
                            do_send(sizeof(DNS_HEADER) + name_len + sizeof(QUESTION) + sizeof(uint16_t ) + sizeof(ANSWER) + sizeof(uint32_t));
                            //do_send(sizeof(DNS_HEADER) + name_len + sizeof(QUESTION) + sizeof(uint16_t ) + sizeof(ANSWER) + sizeof(uint32_t) + 11);
                            loggger << std::setprecision(10) << (double)boost::chrono::system_clock::now().time_since_epoch().count()/1e9 << " " << sender_endpoint_.address().to_string() << " " << hostname.substr(1) << " " << ans_ip.to_string() << std::endl;
                        } else {
                            header->qr = 1;
                            header->aa = 1;
                            header->tc = 0;
                            header->rd = 0;
                            header->ra = 0;
                            header->z = 0;
                            header->rcode = 3;
                            header->q_count = ntohs(1);
                            header->ans_count = ntohs(0);
                            header->auth_count = 0;
                            header->add_count = 0;
                            do_send(sizeof(DNS_HEADER) + name_len + sizeof(QUESTION));
                        }
                    }
                    else
                    {
                        do_receive();
                    }
                });
    }

    void do_send(std::size_t length)
    {
        socket_.async_send_to(
                boost::asio::buffer(data_, length), sender_endpoint_,
                [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/)
                {
                    do_receive();
                });
    }

private:

    udp::socket socket_;
    udp::endpoint sender_endpoint_;
    enum { max_length = 1024 };
    char data_[max_length];

    virtual ipv4_type get_server(const ipv4_type& proxy_ip) = 0;
};

class round_robin_server : public server
{
public:
    round_robin_server(boost::asio::io_service& io_service, const ipv4_type& ip, unsigned short port)
            : server(io_service, ip, port) {
        cur = servers.begin();
        do_receive();
    }

private:
    ip_pool::iterator cur;
    ipv4_type get_server(const ipv4_type& proxy) override {
        ipv4_type &ans = *cur;
        cur++;
        if (cur == servers.end())
            cur = servers.begin();
        return ans;
    }
};

class lsa_server : public server
{
public:
    static std::map<ipv4_type, ipv4_type> content_map;

    static void read_lsa(const std::string &filename) {
        // read lsa records
        std::string sender;
        int32_t seq;
        std::string neighbours;
        std::map<std::string, std::pair<int32_t, std::string>> raw_records;
        std::ifstream file(filename, std::ios::in);
        if (!file.is_open()) {
            std::cerr << "Error: unable to open " << filename << "." << std::endl;
            exit(1);
        }
        while(file >> sender >> seq >> neighbours) {
            auto iter = raw_records.find(sender);
            if (iter != raw_records.end()) {
                if (iter->second.first <= seq)
                    iter->second = std::make_pair(seq, neighbours);
            } else {
                raw_records[sender] = std::make_pair(seq, neighbours);
            }
        }
        file.close();

        std::map<ipv4_type, std::vector<ipv4_type>> reverse_records;
        for (auto iter : raw_records) {
            ipv4_type src_ip = boost::asio::ip::address_v4::from_string(iter.first);

            std::stringstream ss(iter.second.second);
            std::string s;
            while(std::getline(ss, s, ',')) {
                ipv4_type nb_ip = boost::asio::ip::address_v4::from_string(s);
                reverse_records[nb_ip].push_back(src_ip);
            }
        }

        // calculate the shortest path from proxies to servers
        std::map<ipv4_type, std::pair<ipv4_type, int32_t>> proxies_to_servers;
        for (auto s : servers) {

            // calculate shortest distance from all servers to server s
            std::map<ipv4_type, int32_t> to_proxies;
            std::priority_queue<std::pair<int32_t , ipv4_type>> to_expand;
            to_expand.push(std::make_pair(0, s));
            to_proxies[s] = 0;
            while (!to_expand.empty()) {
                auto cur_expand = to_expand.top();
                for (auto p : reverse_records[cur_expand.second]) {
                    auto iter = to_proxies.find(p);
                    if (iter == to_proxies.end()) {
                        to_proxies[p] = cur_expand.first + 1;
                        to_expand.push(std::make_pair(to_proxies[p], p));
                    }
                }
                to_expand.pop();
            }

            // update closest content server of all servers
            for (auto src : to_proxies) {
                auto rec = proxies_to_servers.find(src.first);
                if (rec != proxies_to_servers.end()) {
                    if (rec->second.second > src.second)
                        proxies_to_servers[src.first] = std::make_pair(s, src.second);
                } else {
                    proxies_to_servers[src.first] = std::make_pair(s, src.second);
                }
            }
        }

        // flush routing results into dns
        for (auto rec : proxies_to_servers)
            content_map[rec.first] = rec.second.first;
    }

    lsa_server(boost::asio::io_service &io_service, const ipv4_type &ip, unsigned short port)
            : server(io_service, ip, port) {


    }

private:
    ipv4_type get_server(const ipv4_type &proxy) override {
        auto q = content_map.find(proxy);
        // if from un-recorded proxy, a answer is better than none
        if (q == content_map.end()) {
            std::cout << "Warning: query from unrecorded proxy " << proxy.to_string() << "." << std::endl;
            q = content_map.begin();
        }
        return q->second;
    }
};

server::Mode server::mode = server::round_robin;
ip_pool server::servers;
std::map<ipv4_type, ipv4_type> lsa_server::content_map;

int main(int argc, char* argv[])
{
    try
    {
        if (argc != 7 && argc != 6)
        {
            std::cerr << "Usage: " << argv[0] << " [-r] <log> <ip> <port> <servers> <LSAs>" << std::endl;
            return 1;
        }
        if (argc == 7) {

            if (std::string(argv[1]) == "-r") {
                server::mode = server::round_robin;
            } else {
                std::cerr << "Usage: " << argv[0] << " [-r] <log> <ip> <port> <servers> <LSAs>" << std::endl;
                return 1;
            }
        }
        else {
            server::mode = server::lsa;
        }

        std::string servers_filename(argv[argc - 2]);
        round_robin_server::read_servers(servers_filename);

        unsigned short listen_port = std::stoi(argv[argc-3]);
        ipv4_type listen_ip = ipv4_type::from_string(argv[argc-4]);
        std::string logger_file = argv[argc-5];

        loggger.open(logger_file, std::ios::out|std::ios::app);
        if (!loggger.is_open()) {
            std::cerr << "Fatal: Failed to open " << logger_file << "." << std::endl;
            exit(1);
        }

        boost::asio::io_service io_service;
        if (server::mode == server::round_robin) {
            round_robin_server round_robin_s(io_service, listen_ip, listen_port);
            io_service.run();
        }
        else if (server::mode == server::lsa) {
            std::string lsa_filename(argv[argc - 1]);
            lsa_server::read_lsa(lsa_filename);
            lsa_server lsa_s(io_service, listen_ip, listen_port);
            io_service.run();
        }
    }
    catch (std::exception& e)
    {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}