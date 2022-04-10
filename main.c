#define _GNU_SOURCE 
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <arpa/inet.h>
#define ERR(source) (perror(source),\
		fprintf(stderr,"%s:%d\n",__FILE__,__LINE__),\
		exit(EXIT_FAILURE))

#define MAX_MESSAGE 500
//Maximal length of a TCP/UDP message.
#define N 10
//Each rule after rule no. N inside an fwd message will be ignored.
//Each fwd message after a message no. 10 will be ignored.

int ftable[3], utable[10], uport[10], fwdtable[10][N], fd, bindv;
struct sockaddr_in uaddress[10], fwdaddress[10][N];
volatile sig_atomic_t clients = 0;

int sethandler( void (*f)(int), int sigNo)
{
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = f;
    if(sigaction(sigNo, &act, NULL) == -1) return -1;
    return 0;
}

void sigint_handler(int sig)
{
    TEMP_FAILURE_RETRY(close(fd));
    for(int i=0; i<3; i++)
        TEMP_FAILURE_RETRY(close(ftable[i]));
    for(int i=0; i<10; i++)
        TEMP_FAILURE_RETRY(close(utable[i]));
    for(int i=0; i<10; i++)
    {
        for(int j=0; j<N; j++)
            TEMP_FAILURE_RETRY(close(fwdtable[i][j]));
    }
    TEMP_FAILURE_RETRY(close(bindv));
    _exit(EXIT_SUCCESS);
}

int make_socket(int domain, int type)
{
    int sock;
    sock = socket(domain, type, 0);
    if(sock < 0) ERR("socket creation error");
    return sock;
}

int bind_tcp_socket(uint16_t port)
{
    struct sockaddr_in addr;
    int socketfd, t = 1;
    socketfd = make_socket(PF_INET, SOCK_STREAM);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(port, &rfds);
    if(FD_ISSET(port, &rfds) == 0) ERR("Wrong address");
    if(setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t))) ERR("setsockopt error");
    if(bind(socketfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) ERR("binding error");
    if(listen(socketfd, 3) < 0) ERR("TCP listening error");
    return socketfd;
}

int bind_udp_socket(uint16_t port, int pos)
{
    struct sockaddr_in addr;
    int socketfd, t = 1;
    socketfd = make_socket(PF_INET, SOCK_DGRAM);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t))) ERR("setsockopt error");
    if(bind(socketfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) ERR("binding error");
    uaddress[pos] = addr;
    return socketfd;
}

int bind_fwd_socket(uint16_t port, in_addr_t address, int pos, int pos2) {
    struct sockaddr_in addr;
    int socketfd, t = 1;
    socketfd = make_socket(PF_INET, SOCK_DGRAM);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = address;
    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t))) ERR("setsockopt error");
    fwdaddress[pos][pos2] = addr;
    return socketfd;
}

int find_udp_slot()
{
    int slot = -1;
    for(int i=9; i>=0; i--)
    {
        if(utable[i] == -1)
        slot = i;
    }
    return slot;
}

void fwd_command(char *buf)
{
    int slot = find_udp_slot();
    if(slot != -1)
    {
        char args[2*N+2][20];
        int word = 0, pos = 0;
        for(int i=0; i<MAX_MESSAGE && word<2*N+2; i++)
        {
            if(buf[i] == ' ' || buf[i] == ':')
            {
                args[word][pos] = '\0';
                word++;
                pos = 0;
            }
            else if(buf[i] == '\0')
            {
                args[word][pos] = '\0';
                word++;
                break;
            }
            else
            {
                args[word][pos] = buf[i];
                pos++;
            }
        }
        word = (word - 2)/2;
        if(word <= 0) fprintf(stderr, "no ports provided (no rule created)\n");
        else if (atoi(args[1]) < 1024 || atoi(args[1]) > 65535) fprintf(stderr, "a forbidden port provided (no rule created)\n");
        else
        {
            utable[slot] = bind_udp_socket(atoi(args[1]), slot);
            uport[slot] = atoi(args[1]);
            for(int i=0; i<word; i++)
            {
                fwdtable[slot][i] = bind_fwd_socket(atoi(args[2*i+3]), inet_addr(args[2*i+2]), slot, i);
            }
        }
    }
}

void close_command(char *buf)
{
    int pnumber, counter;
    char port[10];    
    for(int i=6; i<16; i++)
    {
        port[i-6] = buf[i];
        if(buf[i] == ' ' || buf[i] == '\0')
            break;
    }
    pnumber = atoi(port);
    for(int i=0; i<10; i++)
    {
        if(uport[i] == pnumber)
        {
            TEMP_FAILURE_RETRY(close(utable[i]));
            for(int j=0; j<N; j++)
                TEMP_FAILURE_RETRY(close(fwdtable[i][j]));
            utable[i] = -1;
            uport[i] = -1;
            for(int j=0; j<N; j++) fwdtable[i][j] = -1;
            counter++;
        }
    }
    if(counter == 0) fprintf(stderr, "there were no forwarding rules for this port to be closed\n");
}

void show_command(int fd)
{
    char info[25] = "\n-- Forwarding rules --\n";
    char failure[28] = "No forwarding rules found.\n";
    char separator[3] = ", ";
    char line[2] = "\n";
    char message[MAX_MESSAGE + 50], part[MAX_MESSAGE + 50];
    int counter = 0;
    write(fd, (const char*)info, sizeof(info));
    for (int i=0; i<10; i++)
    {
        if(utable[i] != -1)
        {
            counter++;
            snprintf(message, MAX_MESSAGE + 50, "[%d] port no. %d: ", counter, (int)ntohs(uaddress[i].sin_port));
            strcpy(part, inet_ntoa(fwdaddress[i][0].sin_addr));
            strcat(part, ":");
            strcat(message, part);
            snprintf(part, MAX_MESSAGE + 50, "%d", (int)ntohs(fwdaddress[i][0].sin_port));
            strcat(message, part);
            for(int j=1; j<N; j++)
            {
                if(fwdtable[i][j] != -1)
                {
                    strcat(message, separator);
                    strcpy(part, inet_ntoa(fwdaddress[i][j].sin_addr));
                    strcat(part, ":");
                    strcat(message, part);
                    snprintf(part, MAX_MESSAGE + 50, "%d", (int)ntohs(fwdaddress[i][j].sin_port));
                    strcat(message, part);
                }
            }
            strcat(message, line);
            write(fd, (const char*)message, strlen(message) + 1);
        }
    }
    if(counter == 0) write(fd, (const char*)failure, sizeof(failure));
    write(fd, (const char*)line, sizeof(line));
}

void get_tcp_message(int fd)
{
    char buf[MAX_MESSAGE];
    if(TEMP_FAILURE_RETRY(recv(fd, buf, MAX_MESSAGE, MSG_DONTWAIT)) <= 0)
    {
        if(TEMP_FAILURE_RETRY(close(fd) < 0)) ERR("file descriptor closing error\n");
        fd = -1;
    }
    else if (buf[0] == 'f' && buf[1] == 'w' && buf[2] == 'd' && buf[3] == ' ')
        fwd_command(buf);
    else if (buf[0] == 'c' && buf[1] == 'l' && buf[2] == 'o' && buf[3] == 's' && buf[4] == 'e' && buf[5] == ' ')
        close_command(buf);
    else if (buf[0] == 's' && buf[1] == 'h' && buf[2] == 'o' && buf[3] == 'w')
        show_command(fd);    
    else fprintf(stderr, "an unknown command delivered\n");
}

void get_udp_message(int fd, int pos)
{
    int data_size;
    char buf[MAX_MESSAGE];
    socklen_t length = sizeof(uaddress[pos]);
    if((data_size = TEMP_FAILURE_RETRY(recvfrom(fd, buf, MAX_MESSAGE, 0, &(uaddress[pos]), &length))) <= 0 )
        fprintf(stderr, "UDP message retrieval error\n");
    else 
    {
        for(int i=0; i<N; i++)
        {
            length = sizeof(fwdaddress[pos][i]);
            if(fwdtable[pos][i] != -1)
            {
                if(TEMP_FAILURE_RETRY(sendto(fd, buf, data_size, 0, &(fwdaddress[pos][i]), length)) <= 0)
                    fprintf(stderr, "UDP message sending error (rule %d, position %d)\n", pos+1, i+1);
            }
        }
    }
}

int find_tcp_slot()
{
    int slot = -1;
    for(int i=2; i>=0; i--)
    {
        if(ftable[i] == -1)
        slot = i;
    }
    return slot;
}

int get_max_value(fd_set *new_rfds)
{
    FD_ZERO(new_rfds);
    FD_SET(bindv, new_rfds);
    int max_value = bindv;
    for(int i=0; i<3; i++)
    {
        if(ftable[i] != -1)
        {
            FD_SET(ftable[i], new_rfds);
            if (ftable[i] > max_value) max_value = ftable[i];
        }
    }
    for(int i=0; i<10; i++)
    {
        if(utable[i] != -1)
        {
            FD_SET(utable[i], new_rfds);
            if (utable[i] > max_value) max_value = utable[i];
        }
    }
    return max_value;
}

void core_loop(fd_set *new_rfds, sigset_t *oldmask)
{
    int slot, max_value;
    char text[15] = "Hello message\n";
    char denial[38] = "Connection refused: too many clients\n";
    while(1)
    {
        max_value = get_max_value(new_rfds);
        if(pselect(max_value+1, new_rfds, NULL, NULL, NULL, oldmask) > 0)
        {
            if(FD_ISSET(bindv, new_rfds))
            {
                if((fd = TEMP_FAILURE_RETRY(accept(bindv, NULL, NULL))) < 0) ERR("accept");
                else
                {
                    if((slot = find_tcp_slot()) != -1)
                    {
                        write(fd, (const char*)text, sizeof(text));
                        ftable[slot] = fd;
                    }
                    else
                    {
                        write(fd, (const char*)denial, sizeof(denial));
                        if(TEMP_FAILURE_RETRY(close(fd)) < 0) ERR("file descriptor  close error");
                    }
                }
            }
            else
            {
                for(int i=0; i<3; i++)
                {
                    if(FD_ISSET(ftable[i], new_rfds)) 
                    {
                        get_tcp_message(ftable[i]);
                        break;
                    }
                }
                for(int i=0; i<10; i++)
                {
                    if(FD_ISSET(utable[i], new_rfds))
                    {
                        get_udp_message(utable[i], i);
                        break;
                    }
                }
            }
        }
    }
}

int main(int argc, char** argv)
{
    int new_flags;
    if(argc != 2) ERR("wrong number of arguments");
    if(sethandler(SIG_IGN, SIGPIPE)) ERR("SIGPIPE handler setting");
    if(sethandler(sigint_handler, SIGINT)) ERR("SIGINT handler setting");
    bindv = bind_tcp_socket(atoi(argv[1]));
    new_flags = fcntl(bindv, F_GETFL) | O_NONBLOCK;
    fcntl(bindv, F_SETFL, new_flags);
    for(int i=0; i<3; i++) ftable[i] = -1;
    for(int i=0; i<10; i++) 
    {
        utable[i] = -1;
        uport[i] = -1;
        for(int j=0; j<N; j++) fwdtable[i][j] = -1;
    }
    fd_set new_rfds;
    FD_ZERO(&new_rfds);
    FD_SET(bindv, &new_rfds);
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);
    core_loop(&new_rfds, &oldmask);
    return EXIT_FAILURE;
}