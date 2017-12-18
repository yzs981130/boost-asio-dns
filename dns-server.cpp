//
// Created by yzs on 12/2/17.
//

#include "dns-server.h"




server::server(boost::asio::io_service& io_service, int port, std::string interface_address)
        :socket_(io_service, interface_address.empty()?
                 udp::endpoint(ba::ip::udp::v4(), port):
                 udp::endpoint(ba::ip::address().from_string(interface_address), port))
{
    start_receive();
}



void server::start_receive()
{
    socket_.async_receive_from(
            boost::asio::buffer(recv_buffer_), endpoint_,
            boost::bind(&server::handle_receive, this,
                        boost::asio::placeholders::error,
                        boost::asio::placeholders::bytes_transferred));
}

void server::handle_receive(const boost::system::error_code& error,
                                 std::size_t /*bytes_transferred*/)
{
    if (!error || error == boost::asio::error::message_size)
    {
        boost::shared_ptr<std::string> message(
                new std::string("udp test"));

        socket_.async_send_to(boost::asio::buffer(*message), endpoint_,
                              boost::bind(&server::handle_send, this, message,
                                          boost::asio::placeholders::error,
                                          boost::asio::placeholders::bytes_transferred));

        start_receive();
    }
}

void server::packet_generate(bool query) {

    DNS_HEADER header;
    auto& [id, , , aa, , qr, , , , , , , , , ] = header;
    auto [id, rd, tc, aa, opcode, qr, rcode, cd, ad, z, ra, q_count, ans_count, auth_count, add_count] = header;
}
