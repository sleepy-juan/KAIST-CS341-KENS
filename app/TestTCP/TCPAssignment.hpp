/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list>
#include <E/E_TimerModule.hpp>
#include <E/E_TimeUtil.hpp>
using namespace std;

// Constants for Packet
#define WINDOW_SIZE 51200
#define MSS 512

namespace E
{

const Time TIMEOUT = TimeUtil::makeTime(100,TimeUtil::SEC);

/* Context States */
typedef enum CONTEXT_STATES{
	ST_CLOSED,
	ST_LISTEN,
	ST_SYN_SENT,
	ST_SYN_RCVD,
	ST_ESTABLISHED,
	ST_FIN_WAIT_1,
	ST_FIN_WAIT_2,
	ST_TIME_WAIT,
	ST_CLOSE_WAIT,
	ST_CLOSING,
	ST_LAST_ACK,
} State;

/* Chunk for future work, especially timer */
class Chunk{
public:
	UUID syscallUUID;
	int pid, fd;
};

/* Context Info */
class Context{
public: 
	/* socket info */
	State state;
	int pid, fd;
	int backlog;
	bool syn_ready;

	/* connection info */
	uint32_t ip, peer_ip;
	uint16_t port, peer_port;
	bool isBound;

	/* block */
	bool wasAcceptCalled, wasReadCalled, wasWriteCalled;
	UUID syscallUUID;

	size_t argument_count;		// read/write
	void* argument_buffer;
	struct sockaddr_in* argument_address;	// peer

	/* establishing */
	set<Context*> pendings;
	set<Context*> established;

	/* read / write */
	list<Packet *> received;
	list<Packet *> sent;

	/* communication */
	unsigned int seq, ack, peer_seq, peer_ack;
	unsigned int peer_max_ack;
	unsigned short peer_window;
	unsigned int expect_fin;
	unsigned int peer_base_seq, my_base_seq;
	unsigned int recvstart, recvend;

public:
	/* constructor */
	Context() {
		fd = pid = -1;
		ip = port = 0;
		peer_ip = peer_port = 0;
		backlog = 0;
		syscallUUID = 0;
		wasAcceptCalled = wasReadCalled = wasWriteCalled = syn_ready = false;
		isBound = false;
		state = ST_CLOSED;
		seq = ack = 0;
		peer_seq = peer_ack = 0;
		peer_window = WINDOW_SIZE;
	}

	/* shortcut construcgtor for socket() */
	Context(int pid, int fd)
	: Context() {
		this->pid = pid;
		this->fd = fd;
	}

public:
	/* operations */
	void setCommunications(unsigned int seq, unsigned int ack, unsigned int pseq, unsigned int pack){
		this->seq = seq;
		this->ack = ack;
		this->peer_seq = pseq;
		this->peer_ack = pack;
	}

	void setConnections(uint32_t ip, uint16_t port, uint32_t pip, uint16_t pport){
		this->ip = ip;
		this->port = port;
		this->peer_ip = pip;
		this->peer_port = pport;
	}

public:
	/* read & write */
	unsigned int getReadable();
	unsigned int getWritable();
	unsigned int getReceivedSize();
	unsigned int getReceivable();
	unsigned int getSentSize();

	void receive(Packet * packet);
	void send(Packet * packet);
	
	void read(void * buf, unsigned int count);
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	/* Packet Helper functions, used in Debugging */
	Packet* makePacket(uint32_t, uint16_t, uint32_t, uint16_t, unsigned int, unsigned int, bool, bool, bool, unsigned short);
	void fillPacket(Packet*, uint32_t, uint16_t, uint32_t, uint16_t, unsigned int, unsigned int, bool, bool, bool, unsigned short);
	void parsePacket(Packet*, uint32_t*, uint16_t*, uint32_t*, uint16_t*, unsigned int*, unsigned int*, bool*, bool*, bool*, unsigned short*, unsigned short*);
	void printPacket(string, Packet*, bool = false);

	/* contexts */
	list<Context*> all_contexts;

	/* contexts helper functions */
	bool exist_from_all(int pid, int fd);
	bool exist_from_syn(uint32_t ip, uint16_t port);

	void add_to_all(Context* context);
	Context* get_from_all(int pid, int fd);
	Context* get_from_all(uint32_t ip, uint16_t port, uint32_t pip, uint16_t pport);
	Context* pop_from_all(int pid, int fd);
	Context* get_from_syn(uint32_t ip, uint16_t port);

	int how_many_bound(uint16_t port, uint32_t ip = -1);
private:
	virtual void timerCallback(void* payload) final;

	void syscall_socket(UUID syscallUUID, int pid, int domain, int protocol);
	void syscall_close(UUID syscallUUID, int pid, int fd_to_close);
	void syscall_getsockname(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len);
	void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *, socklen_t);
	
	void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t len);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr * addr, socklen_t * addrlen);
	void syscall_getpeername(UUID uuid, int pid, int fd, struct sockaddr * addr, socklen_t * len);
	
	void syscall_read(UUID syscallUUID, int pid, int fd, void * buf, size_t count);
	void syscall_write(UUID syscallUUID, int pid, int fd, void * buf, size_t count);
	
	/* since it uses packet-related functions... */
	void ackReceived(Context * cont, size_t count);
	void cleanup(UUID syscallUUID, int pid, int fd_to_close);			// clean up context(also finish the process)

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */