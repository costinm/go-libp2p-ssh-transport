# go-ws-ssh-transport

Libp2p and IPFS compatible transport using SSH-over-websocket for
security and multiplexing.

This is backward compatible with the "ws" transport: client and server
will negotiate using the standards ws headers, and if SSH is available
on both ends it will be used.

The libp2p transport interface is relatively nice and the higher level
infrastructure and protocols are interesting. Like many others attempting
to reinvent the internet - the protocol is also repeating many mistakes,
in particular creating new security and protocol negotiation schemes,
and failing to interoperate with well established standards.

The Libp2p QUIC transport is a good start in fixing this, by reusing
a well defined standard, TLS + QUIC, and avoiding the round trips for
mux and security negotiation.

This package provides a similar 'combined' transport, using SSH for multiplexing
and security and Websocket for low-level communication.

The choice of WS is needed for interop with JS in browsers. There are few
SSH implementations in javascript as well.

Another option would be TLS+SPDY over Websocket - the multiplexing provided
by SPDY is very similar with SSH. I might add this as an option, using the
built-in WS negotiation instead of the one invented by Libp2p.


# Notes on libp2p interfaces

- lower layer: 'transport.Transport' creates transport.CapableConn (Mux + Security), which
creates MuxedStream. No metadata except public key of the pair.

- network is a higher level - implemented by 'swarm' package. It defines Stream as an extension to MuxedStream,
having an ID and a protocol. It also has metadata, open time, direction and link to the Conn to get the security.

- host is the next layer - basic_host and ipfs host implement it. Adds a local ID, a peerstore (database of peers),
a Mux (protocol.Switch). Has Connect() and SetStreamHandler, NewStream(peer, protocolID...)
Also has a ConnManager and EventBus. High leve introspection as well.


## Helper interfaces

- protocol.Switch - implemented by 'multiformats' package - handles negotiation at high level.
This seems inefficient and ignores the standard capabilities of the protocols. Seems the weakest part of the package.

- PeerStore

- ConnManager: policy to close/keep alive ( Decay ),
Gater, tags for peers. BasicConnMgr implementation using high watermark.

- crypto - custom representation as a PB, base58. Also supports the PEM and raw format.

- RoutedHost - Routing FindPeer(ID)->AddrInfo

- EventBus

# TODO

-

# JS

- https://github.com/billchurch/webssh2
Full HTML terminal.
Based on https://github.com/mscdex/ssh2

- https://github.com/stuicey/SSHy - simpler,
only RSA

-

