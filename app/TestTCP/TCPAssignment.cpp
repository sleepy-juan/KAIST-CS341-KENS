/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{   

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
        NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
        SystemCallInterface(AF_INET, IPPROTO_TCP, host),
        NetworkLog(host->getNetworkSystem()),
        TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet) {
    bool bSYN, bACK, bFIN; 
    unsigned int myip, peer_ip, peer_seq, peer_ack, data_length;
    unsigned short myport, peer_port, peer_window;

    parsePacket(packet, &peer_ip, &peer_port, &myip, &myport, &peer_seq, &peer_ack, &bSYN, &bACK, &bFIN, NULL, &peer_window);
    data_length = packet->getSize() - 54;

    //------------------------- DATA RECEIVED -------------------------//

    if(data_length > 0){
        // find from all possibilities
        Context *context = get_from_all(myip, myport, peer_ip, peer_port);
        if(context == NULL) {
            Context *syn_context = get_from_syn(myip, myport);
            for(Context *candidate : syn_context->established){
                if(candidate->peer_ip == peer_ip && candidate->peer_port == peer_port){
                    context = candidate;
                    break;
                }
            }
        }

        if(context != NULL){
            context->peer_window = peer_window;
            if(context->getReceivedSize() + packet->getSize() <= WINDOW_SIZE){
                Packet *newpacket = clonePacket(packet);
                context->receive(newpacket);
                if(context->wasReadCalled && context->getReadable() > 0) {
                    unsigned int length = context->getReadable();
                    if (length > context->argument_count) 
                        length = context->argument_count;
                    context->read(context->argument_buffer, length);
                    context->wasReadCalled = false;
                    ackReceived(context, length);
                    returnSystemCall(context->syscallUUID, length);
                }

                Packet *ackpacket = makePacket(myip, myport, peer_ip, peer_port, context->seq, context->ack, false, true, false, context->getReceivable());
                sendPacket("IPv4", ackpacket);
            }
        }
    }
    freePacket(packet);

    //------------------------- SYN -------------------------//

    if(bSYN){
        Context *context = get_from_syn(myip, myport);//findFromSynready(mp(myip, myport));
        for(Context* candidate : context->pendings){
            if(candidate->ip == myip && candidate->port == myport && candidate->peer_ip == peer_ip && candidate->peer_port == peer_port){
                context = candidate;    // find pending socket getting syn packet
                break;    
            }
        }

        // getting all contexts 
        if(context == NULL) // no pending socket
            context = get_from_all(myip, myport, peer_ip, peer_port);
        if(context == NULL){
            Context *syn_context = get_from_syn(myip, myport);
            for(Context *candidate : syn_context->established){
                if(candidate->peer_ip == peer_ip && candidate->peer_port == peer_port){
                    context = candidate;
                    break;
                }
            }
        }

        if(context != NULL){
            if(context->state == ST_LISTEN && context->backlog > context->pendings.size()){
                Context *candidate = new Context;
                candidate->peer_base_seq = peer_seq;
                candidate->recvstart = peer_seq + 1;
                candidate->recvend = peer_seq + 1;
                candidate->setCommunications(random(), peer_seq+1, peer_seq, peer_ack);
                candidate->setConnections(myip, myport, peer_ip, peer_port);
                candidate->my_base_seq = candidate->seq;
                candidate->isBound = true;
                candidate->state = ST_SYN_RCVD;

                context->pendings.insert(candidate);

                Packet *synackpacket = makePacket(myip, myport, peer_ip, peer_port, candidate->my_base_seq, candidate->ack, true, true, false, WINDOW_SIZE);
                sendPacket("IPv4", synackpacket);
                candidate->seq++;
            }
            else{
                if(context->state == ST_SYN_SENT)
                {
                    context->peer_base_seq = peer_seq;
                    context->recvstart = peer_seq + 1;
                    context->recvend = peer_seq + 1;
                    context->setCommunications(context->seq, peer_seq+1, peer_seq, peer_ack);
                    context->setConnections(myip, myport, peer_ip, peer_port);
                    context->state = ST_SYN_RCVD;
                }

                Packet *ackpacket = makePacket(myip, myport, peer_ip, peer_port, context->my_base_seq + 1, context->ack, false, true, false, WINDOW_SIZE);
                sendPacket("IPv4", ackpacket);
            }
        }
    }

    //------------------------- ACK -------------------------//

    if(bACK) {
        Context *context = get_from_all(myip, myport, peer_ip, peer_port); // find all
        if(context == NULL) {
            Context *syn_context = get_from_syn(myip, myport);
            for(Context *candidate : syn_context->established){
                if(candidate->peer_ip == peer_ip && candidate->peer_port == peer_port){
                    context = candidate;
                    break;
                }
            }
        }

        if(context == NULL){
            // find all candidates and include them
            Context *ready = get_from_syn(myip, myport);
            for(Context *candidate : ready->pendings){
                if(candidate->peer_ip == peer_ip && candidate->peer_port == peer_port && candidate->state == ST_SYN_RCVD){
                    context = candidate;
                    break;
                }
            }

            // something found
            if(context != NULL){
                context->peer_window = peer_window;
                context->state = ST_ESTABLISHED;
                context->peer_ack = context->peer_max_ack = peer_ack;

                ready->pendings.erase(ready->pendings.find(context));
                ready->established.insert(context);

                if(ready->wasAcceptCalled){
                    Context *accepted = *ready->established.begin();
                    ready->established.erase(ready->established.begin());

                    int newfd = createFileDescriptor(ready->pid);
                    accepted->pid = ready->pid;
                    accepted->fd = newfd;

                    add_to_all(accepted);

                    ready->wasAcceptCalled = false;
                    ready->argument_address->sin_family = AF_INET;
                    ready->argument_address->sin_port = accepted->peer_port;
                    ready->argument_address->sin_addr.s_addr = accepted->peer_ip;
                    returnSystemCall(ready->syscallUUID, newfd);
                }
            }
        }
        else{ // context found
            context->peer_window = peer_window;
            context->peer_ack = peer_ack;
            
            if(context->peer_max_ack - context->my_base_seq < peer_ack - context->my_base_seq && context->expect_fin != peer_ack){
                context->peer_max_ack = peer_ack;
            }

            // clear sent and acked
            while(context->sent.size() > 0) {
                Packet* packet = *context->sent.begin();
                unsigned int s_seq, s_len = packet->getSize() - 54;
                packet->readData(38, &s_seq, 4);
                s_seq = ntohl(s_seq) - context->my_base_seq;

                if(s_seq + s_len <= context->peer_max_ack - context->my_base_seq)
                {
                    freePacket(*context->sent.begin());
                    context->sent.erase(context->sent.begin());
                }
                else break;
            }

            if(context->wasWriteCalled && context->getWritable() > 0){
                syscall_write(context->syscallUUID, context->pid, context->fd, context->argument_buffer, context->argument_count);
            }
            if(peer_ack == context->expect_fin){  // ack && fin
                switch(context->state){
                    case ST_FIN_WAIT_1:
                        context->state = ST_FIN_WAIT_2;
                        break;
                    case ST_CLOSING:
                    {
                        Chunk * payload = new Chunk;              
                        context->state = ST_TIME_WAIT;
                        addTimer((void *)payload, TIMEOUT);
                    }
                        break;
                    case ST_LAST_ACK:
                        context->state = ST_CLOSED;
                        cleanup(context->syscallUUID, context->pid, context->fd);
                        break;
                    default:
                        break;
                }
            }
            else if(context->state == ST_SYN_RCVD)
            {
                context->state = ST_ESTABLISHED;
                context->peer_max_ack = peer_ack;
                returnSystemCall(context->syscallUUID, 0);
            }
        }
    }

    //------------------------- FIN -------------------------//

    if(bFIN) {
        // search context from all possibilities
        Context *context = get_from_all(myip, myport, peer_ip, peer_port);
        if(context == NULL) {
            Context *syn_context = get_from_syn(myip, myport);
            for(Context *candidate : syn_context->established){
                if(candidate->peer_ip == peer_ip && candidate->peer_port == peer_port){
                    context = candidate;
                    break;
                }
            }
        }

        if(context != NULL) {
            context->peer_window = peer_window;
            
            if(peer_seq == context->ack){
                if(context->wasReadCalled)
                {
                    context->wasReadCalled = false;
                    returnSystemCall(context->syscallUUID , -1);
                }
                context->ack++;

                switch(context->state)
                {
                    case ST_ESTABLISHED:
                        context->peer_seq = peer_seq;
                        context->state = ST_CLOSE_WAIT;
                        break;
                    case ST_FIN_WAIT_1:
                        context->peer_seq = peer_seq;
                        context->state = ST_CLOSING;
                        break;
                    case ST_FIN_WAIT_2:
                    {
                        context->peer_seq = peer_seq;
                        context->state = ST_TIME_WAIT;
                        
                        Chunk * payload = new Chunk; 
                        payload->syscallUUID = context->syscallUUID;
                        payload->fd = context->fd;
                        payload->pid = context->pid;
                        addTimer((void *)payload, TIMEOUT);
                    }
                        break;
                    default: 
                        break;
                }
            }

            // send response: ack
            Packet *ackpacket = makePacket(myip, myport, peer_ip, peer_port, context->seq, context->ack, false, true, false, WINDOW_SIZE);
            sendPacket("IPv4", ackpacket);
        }
    } 
}

void TCPAssignment::timerCallback(void* raw_payload) {
    // assume that there is no packet loss
    Chunk * payload = (Chunk *)raw_payload;
    cleanup(payload->syscallUUID, payload->pid, payload->fd);
    delete payload;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int protocol) {
    int fd = createFileDescriptor(pid);
    Context* context = new Context(pid, fd);
    add_to_all(context);
    returnSystemCall(syscallUUID, fd);
}

void TCPAssignment::cleanup(UUID syscallUUID, int pid, int fd) {
    // clean up the context and do some related work(return system call)
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = pop_from_all(pid, fd);
    for(Packet* p : get->received){
        freePacket(p);
    }
    get->received.clear();

    for(Packet* p : get->sent){
        freePacket(p);
    }
    get->sent.clear();

    get->pendings.clear();
    get->established.clear();
    
    delete get;
    removeFileDescriptor(pid, fd);
    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *context = get_from_all(pid, fd);
    if(context -> wasReadCalled){   // impossible to read on this state
        context->wasReadCalled = false;
        returnSystemCall(context->syscallUUID, -1);
        return;
    }

    switch(context->state){
    case ST_ESTABLISHED:
    case ST_SYN_RCVD:
        context->state = ST_FIN_WAIT_1;
        context->syscallUUID = syscallUUID;
        break;
    case ST_CLOSE_WAIT:
        context->state = ST_LAST_ACK;
        context->syscallUUID = syscallUUID;
        break;
    case ST_SYN_SENT:
        context->state = ST_CLOSED;
    default:
        cleanup(syscallUUID, pid, fd);
        return;
    }

    if(context->state == ST_SYN_SENT){            // no need to do something; clean up.
        cleanup(syscallUUID, pid, fd);
        return;
    }

    Packet *finpacket = makePacket(context->ip, context->port, context->peer_ip, context->peer_port, context->seq, context->ack, false, false, true, WINDOW_SIZE);
    sendPacket("IPv4", finpacket);
    context->expect_fin = context->seq + 1;
    context->seq++;
    
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);
    if(get->isBound){   // already bound
        returnSystemCall(syscallUUID, -1);
        return;
    }

    struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;
    uint32_t ip = in_addr->sin_addr.s_addr;
    uint16_t port = in_addr->sin_port;

    if(ip == INADDR_ANY && how_many_bound(port) > 0){
        returnSystemCall(syscallUUID, -1);  // port exists
        return;
    }

    if(how_many_bound(port, ip) || how_many_bound(port, 0)){    // double bind
        returnSystemCall(syscallUUID, -1);
        return;
    }

    get->ip = ip;
    get->port = port;
    get->isBound = true;
    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);

    struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;
    in_addr->sin_family = AF_INET;
    in_addr->sin_port = get->port;
    in_addr->sin_addr.s_addr = get->ip;
    *len = sizeof(struct sockaddr_in);

    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * len) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);

    struct sockaddr_in * in_addr = (struct sockaddr_in *)addr;
    in_addr->sin_family = AF_INET;
    in_addr->sin_port = get->peer_port;
    in_addr->sin_addr.s_addr = get->peer_ip;
    *len = sizeof(struct sockaddr_in);

    returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);
    if(get->state == ST_SYN_SENT || get->state == ST_ESTABLISHED){
        returnSystemCall(syscallUUID, -1);  // cannot connect on this state
        return;
    }

    struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
    uint32_t server_ip = addr_in->sin_addr.s_addr;
    uint16_t server_port = addr_in->sin_port;
    if(!get->isBound){
        // ip
        int interface = getHost()->getRoutingTable((const uint8_t *)&server_ip);
        while(getHost()->getIPAddr((uint8_t *)&(get->ip), interface)==false);

        // port
        get->port = random() % 65536;   // 2bytes
        while(how_many_bound(get->port, get->ip)){
            get->port = random() % 65536;
        }

        get->isBound = true;
    }

    Packet *synpacket = makePacket(get->ip, get->port, server_ip, server_port, get->seq, 0, true, false, false, WINDOW_SIZE);
    sendPacket("IPv4", synpacket);

    get->syscallUUID = syscallUUID;
    get->state = ST_SYN_SENT;
    get->peer_ip = server_ip;
    get->peer_port = server_port;

    get->syn_ready = true;
    get->seq++;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);
    if(exist_from_syn(get->ip, get->port) || exist_from_syn(0, get->port)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    if(!get->isBound){  // not bound yet
        returnSystemCall(syscallUUID, -1);
        return;
    }

    get->backlog = backlog;
    get->state = ST_LISTEN;
    get->syn_ready = true;
    returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);

    if(get->state != ST_LISTEN) {          // or, cannot accept
        this->returnSystemCall(syscallUUID, -1);
        return;
    }

    if(get->established.empty()){   // block
        get->wasAcceptCalled = true;
        get->syscallUUID = syscallUUID;
        *addrlen = sizeof(struct sockaddr_in);
        get->argument_address = (struct sockaddr_in*) addr;
        return;
    }

    // accept
    Context *accepted = *(get->established.begin());
    get->established.erase(get->established.begin());

    int newfd = createFileDescriptor(pid);
    accepted->fd = newfd;
    accepted->pid = pid;

    add_to_all(accepted);

    get->wasAcceptCalled = false;

    *addrlen = sizeof(struct sockaddr_in);
    struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
    addr_in->sin_family = AF_INET;
    addr_in->sin_port = accepted->peer_port;
    addr_in->sin_addr.s_addr = accepted->peer_ip;
    returnSystemCall(syscallUUID, newfd);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void * buf, size_t count) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);
    if(get->getReadable() > 0){
        unsigned int length = get->getReadable();
        if(count < length) length = count;

        get->read(buf, length);
        get->wasReadCalled = false;
        ackReceived(get, length);
        returnSystemCall(syscallUUID, length);
        return;
    }

    // block
    get->wasReadCalled = true;
    get->syscallUUID = syscallUUID;
    get->argument_buffer = buf;
    get->argument_count = count;
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void * buf, size_t count) {
    if(!exist_from_all(pid, fd)){
        returnSystemCall(syscallUUID, -1);
        return;
    }

    Context *get = get_from_all(pid, fd);
    if(get->getWritable() > 0) {   
        unsigned int length = std::min((unsigned int)count, get->getWritable());
        for(unsigned int start = 0; start < length; start += MSS) {
            unsigned int end = std::min(start + MSS, length);

            // make header+payload
            uint8_t * payload = new uint8_t[54 + end - start];
            memset((void*)payload, 0, sizeof(payload));
            *(uint32_t *)(payload + 26) = get->ip;
            *(uint32_t *)(payload + 30) = get->peer_ip;
            *(unsigned short *)(payload + 34) = get->port;
            *(unsigned short *)(payload + 36) = get->peer_port;
            *(unsigned int *)(payload + 38) = htonl(get->seq);
            *(unsigned int *)(payload + 42) = htonl(get->ack);
            *(unsigned char *)(payload + 46) = (5 << 4);
            *(unsigned char *)(payload + 47) = 16;
            *(unsigned short *)(payload + 48) = htons(WINDOW_SIZE - get->getReceivedSize());
            *(unsigned short *)(payload + 50) = 0;
            for(int i = start; i < end; i++) payload[i-start + 54] = *((uint8_t *)buf + i);
            unsigned int checksum = ~NetworkUtil::tcp_sum(get->ip, get->peer_ip, payload + 34, 20 + end - start);
            *(unsigned short *)(payload + 50) = htons(checksum);
            
            // send Packet
            Packet* packet = allocatePacket(54 + end - start);
            packet->writeData(0, payload, packet->getSize());       // copy all
            sendPacket("IPv4", packet);
            delete [] payload;  

            // insert & proc
            get->send(clonePacket(packet));
            get->seq += end-start;
        }

        returnSystemCall(syscallUUID, length);
        get->wasWriteCalled = false;
        return;
    }

    get->wasWriteCalled = true;
    get->syscallUUID = syscallUUID;
    get->argument_buffer = buf;
    get->argument_count = count;
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) {
    switch(param.syscallNumber)
    {
    case SOCKET:
        this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
        break;
    case CLOSE:
        this->syscall_close(syscallUUID, pid, param.param1_int);
        break;
    case READ:
        this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        break;
    case WRITE:
        this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
        break;
    case CONNECT:
        this->syscall_connect(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
        break;
    case LISTEN:
        this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
        break;
    case ACCEPT:
        this->syscall_accept(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr*>(param.param2_ptr),
                static_cast<socklen_t*>(param.param3_ptr));
        break;
    case BIND:
        this->syscall_bind(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr *>(param.param2_ptr),
                (socklen_t) param.param3_int);
        break;
    case GETSOCKNAME:
        this->syscall_getsockname(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr *>(param.param2_ptr),
                static_cast<socklen_t*>(param.param3_ptr));
        break;
    case GETPEERNAME:
        this->syscall_getpeername(syscallUUID, pid, param.param1_int,
                static_cast<struct sockaddr *>(param.param2_ptr),
                static_cast<socklen_t*>(param.param3_ptr));
        break;
    default:
        assert(0);
    }
}

unsigned int Context::getReadable() {
    return recvend - recvstart;
}

unsigned int Context::getWritable() {
    unsigned int length = 0;
    if(getSentSize() < peer_window) 
        length = peer_window - getSentSize();
    if(getSentSize() < WINDOW_SIZE){
        if(length > 0)
            length = std::min(length, WINDOW_SIZE - getSentSize());
        else
            length = WINDOW_SIZE - getSentSize();
    }
    return length;
}

unsigned int Context::getReceivable() {
    return WINDOW_SIZE - getReceivedSize();
}

unsigned int Context::getReceivedSize() {
    unsigned int length = 0;
    for(Packet *packet : received) 
        length += packet->getSize();
    return length;
}

unsigned int Context::getSentSize() {
    unsigned int length = 0;
    for(Packet *packet : this->sent) 
        length += packet->getSize();
    return length;
}

void Context::send(Packet * packet) {
    unsigned int p_seq, p_len = packet->getSize() - 54;
    packet->readData(38, &p_seq, 4);
    p_seq = ntohl(p_seq) - my_base_seq;

    list<Packet*>::iterator iter = sent.begin();
    for(; iter != sent.end(); iter++){
        unsigned int s_seq, s_len = packet->getSize() - 54;
        packet->readData(38, &s_seq, 4);
        s_seq = ntohl(s_seq) - my_base_seq;

        if(s_seq + s_len > p_seq + p_len)
            break;
    }
    sent.insert(iter, packet);
}

void Context::receive(Packet * packet) {
    unsigned int p_seq, p_len = packet->getSize() - 54;
    packet->readData(38, &p_seq, 4);
    p_seq = ntohl(p_seq) - peer_base_seq;

    list<Packet*>::iterator iter = received.begin();
    for(; iter != received.end(); iter++){
        unsigned int s_seq, s_len = packet->getSize() - 54;
        packet->readData(38, &s_seq, 4);
        s_seq = ntohl(s_seq) - peer_base_seq;

        if(s_seq + s_len > p_seq + p_len)
            break;
    }
    received.insert(iter, packet);

    iter = received.begin();
    for(; iter != received.end(); iter++)
    {
        unsigned int s_seq, s_len = packet->getSize() - 54;
        packet->readData(38, &s_seq, 4);
        s_seq = ntohl(s_seq) - peer_base_seq;

        if(s_seq <= recvend - peer_base_seq) {
            recvend = std::max(recvend - peer_base_seq, s_seq + s_len) + peer_base_seq;
        }
    }
    ack = recvend;
}

void TCPAssignment::ackReceived(Context * context, size_t count){
    while(context->received.size() > 0){
        Packet* packet = *context->received.begin();
        unsigned int r_seq, r_len = packet->getSize() - 54;
        packet->readData(38, &r_seq, 4);
        r_seq = ntohl(r_seq) - context->peer_base_seq;

        if(r_seq + r_len <= context->recvstart - context->peer_base_seq + count){
            // drop the packet
            freePacket(*context->received.begin());
            context->received.erase(context->received.begin());
        }
        else if(r_seq < context->recvstart - context->peer_base_seq + count && context->recvstart - context->peer_base_seq + count < r_seq + r_len) {
            // or, cut the packet into proper size
            int cut = context->recvstart + count - context->peer_base_seq - r_seq;

            Packet *cut_packet = allocatePacket(packet->getSize() - cut);
            uint8_t *copy = new uint8_t[packet->getSize() - count];
            packet->readData(0, copy, 54);
            *(unsigned int*)(copy + 38) = htonl(r_seq + context->peer_base_seq + count);

            packet->readData(54 + cut, copy + 54, packet->getSize() - 54 - cut);
            cut_packet->writeData(0, copy, cut_packet->getSize());
            delete []copy;

            freePacket(packet);
            context->received.erase(context->received.begin());
            context->received.push_front(cut_packet);               // push back into front (ordering)
        }
        else{
            break;
        }
    }
    // update receiver window
    context->recvstart += count;
}

void Context::read(void * buf, unsigned int count) {
    for(Packet* packet : received){
        unsigned int r_seq, r_len = packet->getSize() - 54;
        packet->readData(38, &r_seq, 4);
        r_seq = ntohl(r_seq) - peer_base_seq;

        unsigned int from = std::max(r_seq, recvstart - peer_base_seq);
        unsigned int to = std::min(r_seq + r_len, recvstart - peer_base_seq + count);
        packet->readData(54 + from - r_seq, ((char*)buf + (from + peer_base_seq - recvstart)), to-from);
    }
}

//------------------------- CONTEXT MANAGER -------------------------//

bool TCPAssignment::exist_from_all(int pid, int fd){
    for(Context* c : all_contexts){
        if(c->pid == pid && c->fd == fd) return true;
    }
    return false;
}

bool TCPAssignment::exist_from_syn(uint32_t ip, uint16_t port){
    for(Context* c: all_contexts){
        if(c->ip == ip && c->port == port){
            if(c->syn_ready)
                return true;
        }
        if(c->ip == 0 && c->port == port){
            if(c->syn_ready)
                return c;
        }
    }
    return false;
}

void TCPAssignment::add_to_all(Context* context){
    all_contexts.push_back(context);
}

Context* TCPAssignment::get_from_all(int pid, int fd){
    for(Context* c : all_contexts){
        if(c->pid == pid && c->fd == fd) return c;
    }
    return NULL;
}

Context* TCPAssignment::get_from_all(uint32_t ip, uint16_t port, uint32_t pip, uint16_t pport){
    for(Context* c: all_contexts){
        if(c->ip == ip && c->port == port && c->peer_ip == pip && c->peer_port == pport){
            return c;
        }
    }
    return NULL;
}

Context* TCPAssignment::pop_from_all(int pid, int fd){
    list<Context*>::iterator iter;
    for(iter = all_contexts.begin(); iter != all_contexts.end(); iter++){
        if((*iter)->pid == pid && (*iter)->fd == fd){
            all_contexts.erase(iter);
            return (*iter);
        }
    }
    return NULL;
}

Context* TCPAssignment::get_from_syn(uint32_t ip, uint16_t port){
    for(Context* c: all_contexts){
        if(c->ip == ip && c->port == port){
            if(c->syn_ready)
                return c;
        }
        if(c->ip == 0 && c->port == port){
            if(c->syn_ready)
                return c;
        }
    }
    return NULL;
}

int TCPAssignment::how_many_bound(uint16_t port, uint32_t ip){
    int num = 0;
    for(Context* c: all_contexts){
        if(ip == -1){
            if(c->isBound && c->port == port)
                num++;
        }
        else{
            if(c->isBound && c->ip == ip && c->port == port)
                num++;
        }
    }
    return num;
}

//------------------------- PACKET HELPERS -------------------------//

Packet* TCPAssignment::makePacket(
    uint32_t ip,
    uint16_t port,
    uint32_t peer_ip,
    uint16_t peer_port,
    unsigned int seq, 
    unsigned int ack, 
    bool bsyn, 
    bool back, 
    bool bfin, 
    unsigned short window)
{
    uint8_t tcp_header[20] = {0};

    *(unsigned short *)(tcp_header + 0) = port;
    *(unsigned short *)(tcp_header + 2) = peer_port;
    *(unsigned int *)(tcp_header + 4) = htonl(seq);
    *(unsigned int *)(tcp_header + 8) = htonl(ack);
    *(unsigned char *)(tcp_header + 12) = (5 << 4);
    int flag = 0;
    if(bsyn) flag += 1 << 1;
    if(back) flag += 1 << 4;
    if(bfin) flag += 1;
    *(unsigned char *)(tcp_header + 13) = flag;
    *(unsigned short *)(tcp_header + 14) = htons(window);
    *(unsigned short *)(tcp_header + 16) = 0;

    unsigned short checksum = ~NetworkUtil::tcp_sum(ip, peer_ip, tcp_header, 20);
    *(unsigned short *)(tcp_header + 16) = htons(checksum);

    Packet* packet = allocatePacket(54);
    packet->writeData(26, &ip, 4);
    packet->writeData(30, &peer_ip, 4);
    packet->writeData(34, tcp_header, 20);

    return packet;
}

void TCPAssignment::fillPacket(
    Packet* packet,
    uint32_t ip,
    uint16_t port,
    uint32_t peer_ip,
    uint16_t peer_port,
    unsigned int seq, 
    unsigned int ack, 
    bool bsyn, 
    bool back, 
    bool bfin, 
    unsigned short window)
{
    uint8_t tcp_header[20] = {0};

    *(unsigned short *)(tcp_header + 0) = port;
    *(unsigned short *)(tcp_header + 2) = peer_port;
    *(unsigned int *)(tcp_header + 4) = htonl(seq);
    *(unsigned int *)(tcp_header + 8) = htonl(ack);
    *(unsigned char *)(tcp_header + 12) = (5 << 4);
    int flag = 0;
    if(bsyn) flag += 1 << 1;
    if(back) flag += 1 << 4;
    if(bfin) flag += 1;
    *(unsigned char *)(tcp_header + 13) = flag;
    *(unsigned short *)(tcp_header + 14) = htons(window);
    *(unsigned short *)(tcp_header + 16) = 0;

    unsigned short checksum = ~NetworkUtil::tcp_sum(ip, peer_ip, tcp_header, 20);
    *(unsigned short *)(tcp_header + 16) = htons(checksum);

    packet->writeData(26, &ip, 4);
    packet->writeData(30, &peer_ip, 4);
    packet->writeData(34, tcp_header, 20);
}

void TCPAssignment::parsePacket(
    Packet* packet,
    uint32_t* ip,
    uint16_t* port,
    uint32_t* peer_ip,
    uint16_t* peer_port,
    unsigned int* seq, 
    unsigned int* ack, 
    bool* bsyn, 
    bool* back, 
    bool* bfin, 
    unsigned short* checksum,
    unsigned short* window)
{
    if(ip != NULL) packet->readData(14+12, ip, 4);
    if(peer_ip != NULL) packet->readData(14+16, peer_ip, 4);
    if(port != NULL) packet->readData(34, port, 2);
    if(peer_port != NULL) packet->readData(34+2, peer_port, 2);
    if(seq != NULL) {
        packet->readData(34+4, seq, 4);
        *seq = ntohl(*seq);
    }
    if(ack != NULL) {
        packet->readData(34+8, ack, 4);
        *ack = ntohl(*ack);
    }
    if(window != NULL) {
        packet->readData(34+14, window, 2);
        *window = ntohs(*window);
    }
    if(checksum != NULL){
        packet->readData(34+16, checksum, 2);
        *checksum = ntohs(*checksum);
    }

    char flag;
    packet->readData(34+13, &flag, 1);
    if(bsyn != NULL) (*bsyn) = !!(flag & (1 << 1));
    if(back != NULL) (*back) = !!(flag & (1 << 4));
    if(bfin != NULL) (*bfin) = !!(flag & 1);
}

void TCPAssignment::printPacket(string title, Packet *packet, bool bPrint){
    uint32_t ip, peer_ip;
    uint16_t port, peer_port;
    bool bSYN, bACK, bFIN;
    unsigned int peer_seq, peer_ack;
    unsigned short peer_window;
    size_t data_size;

    static unsigned int s_peer_seq, s_peer_ack;
    static unsigned short s_peer_window;
    static size_t s_data_size;
    static bool sSYN, sACK, sFIN;

    // parse packet
    parsePacket(packet, &peer_ip, &peer_port, &ip, &port, &peer_seq, &peer_ack, &bSYN, &bACK, &bFIN, NULL, &peer_window);
    data_size = packet->getSize() - 54;

    if(false 
        && s_peer_ack != peer_ack && s_peer_seq != peer_seq){
        cout<<"//--------------------------------------------------"<<endl;
        cout<<"// "<<title<<endl;
        cout<<"//"<<endl;
        cout<<"// My Address ("<<ip<<", "<<port<<")"<<endl;
        cout<<"// From ("<<peer_ip<<", "<<peer_port<<")"<<endl;
        cout<<"// (Syn, Ack, Fin) == ("<<bSYN<<", "<<bACK<<", "<<bFIN<<")"<<endl;
        cout<<"// SeqNum: "<<peer_seq<<endl;
        cout<<"// AckNum: "<<peer_ack<<endl;
        cout<<"// Window: "<<peer_window<<endl;
        cout<<"// DataSize: "<<data_size<<endl;
        cout<<endl;
    }

    s_peer_seq = peer_seq;
    s_peer_ack = peer_ack;
    s_peer_window = peer_window;
    s_data_size = data_size;
    sSYN = bSYN;
    sACK = bACK;
    sFIN = bFIN;
}


}