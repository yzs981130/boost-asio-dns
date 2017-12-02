//
// Created by yzs on 12/2/17.
//

#ifndef BOOST_ASIO_DNS_DNS_SERVER_H
#define BOOST_ASIO_DNS_DNS_SERVER_H


#include "common.h"

using boost::asio::ip::udp;

class server
{
public:
    server(boost::asio::io_service& io_service, int port = 5353, std::string interface_address = "");


private:
    void start_receive();

    void handle_receive(const boost::system::error_code& error,
                        std::size_t /*bytes_transferred*/);

    void handle_send(boost::shared_ptr<std::string> /*message*/,
                     const boost::system::error_code& /*error*/,
                     std::size_t /*bytes_transferred*/)
    {
    }

    udp::socket socket_;
    udp::endpoint endpoint_;
    boost::array<char, 1> recv_buffer_;
};

#endif //BOOST_ASIO_DNS_DNS_SERVER_H
