# OS-classes
This is a single-threaded program created for Operating Systems classes at my university. The solution is written in C language.

*From the 'task requirements' description:* <br />
The program is responsible for forwarding incoming UDP datagrams. The program is configured via administrative TCP protocol. The program takes one positional argument: TCP port the program will listen on for incoming administrative connections.

The main process creates a TCP socket bound to localhost address port passed as an argument. Therefore, it won’t accept connections from different hosts. At most 3 connections are allowed – if 4th client would like to establish connection the server should reply with an informative message and drop the connection.

The server simultaneously handles one line string configuration commands received from all clients along with UDP forwarding according to configuration. By default it forwards nothing (so it has no UPD sockets at the very beginning). Available commands are: 
- **fwd \<port<sub>L</sub>> \<IP<sub>1</sub>:port<sub>1</sub>> … \<IP<sub>n</sub>:port<sub>n</sub>>** (e.g. *fwd 1500 127.0.0.1:2000*)<br />
Opens a new UDP socket and starts forwarding datagrams incoming on UDP port to all endpoints given in IP:port list. Up to 10 forwarding rules are allowed.

- **close \<port>** <br />
Stops forwarding on given port and closes corresponding UDP socket. 
- **show** <br />
Sends to a client an active configuration (open UDP ports with forwarding rules and filtering).
