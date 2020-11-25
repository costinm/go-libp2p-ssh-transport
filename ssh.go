package websocket

import (
	"errors"
	"fmt"
	"net"

	"net/http"
	"time"

	"github.com/docker/spdystream"
	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"golang.org/x/crypto/ssh"
)

// errClosed is returned when trying to accept a stream from a closed connection
var errClosed = errors.New("conn closed")

type stream struct {
	ch ssh.Channel
}

func (c *stream) Read(p []byte) (n int, err error) {
	return c.ch.Read(p)
}

func (c *stream) Write(p []byte) (n int, err error) {
	return c.ch.Write(p)
}

func (c *stream) Close() error {
	return c.ch.Close()
}

func (c *stream) CloseRead() error {
	return c.ch.Close()
}

func (c *stream) Reset() error {
	return c.ch.Close()
}

func (c *stream) CloseWrite() error {
	return c.ch.CloseWrite()
}

func (c *stream) SetDeadline(t time.Time) error {
	return nil
}

func (c *stream) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *stream) SetWriteDeadline(t time.Time) error {
	return nil
}

// Conn is a connection to a remote peer.
type sshconn struct {
	sc ssh.Conn

	streamQueue chan ssh.Channel

	closed chan struct{}

	scl      *ssh.Client

	// Original websocket con, wrapped with remote/local addr
	wsCon net.Conn
}

func (c *sshconn) LocalPeer() peer.ID {
	panic("implement me")
}

func (c *sshconn) LocalPrivateKey() ic.PrivKey {
	panic("implement me")
}

func (c *sshconn) RemotePeer() peer.ID {
	panic("implement me")
}

func (c *sshconn) RemotePublicKey() ic.PubKey {
	panic("implement me")
}

func (c *sshconn) LocalMultiaddr() ma.Multiaddr {
	r, _ := manet.FromNetAddr(c.wsCon.LocalAddr())
	return r
}

func (c *sshconn) RemoteMultiaddr() ma.Multiaddr {
	r, _ := manet.FromNetAddr(c.wsCon.RemoteAddr())
	return r
}

func (c *sshconn) Transport() transport.Transport {
	panic("implement me")
}

func (c *sshconn) Close() error {
	err := c.sc.Close()
	if !c.IsClosed() {
		close(c.closed)
	}
	return err
}

func (c *sshconn) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}



// OpenStream creates a new stream.
func (c *sshconn) OpenStream() (mux.MuxedStream, error) {
	s, _, err := c.sc.OpenChannel("", nil)
	if err != nil {
		return nil, err
	}

	return &stream{ch: s}, nil
}


// AcceptStream accepts a stream opened by the other side.
func (c *sshconn) AcceptStream() (mux.MuxedStream, error) {
	if c.IsClosed() {
		return nil, errClosed
	}

	select {
	case <-c.closed:
		return nil, errClosed
	case s := <-c.streamQueue:
		return &stream{ch:s}, nil
	}
}

// serve accepts incoming streams and places them in the streamQueue
func (c *sshconn) serve() {
	c.spdyConn().Serve(func(s *spdystream.Stream) {
		// Flow control and backpressure of Opening streams is broken.
		// I believe that spdystream has one set of workers that both send
		// data AND accept new streams (as it's just more data). there
		// is a problem where if the new stream handlers want to throttle,
		// they also eliminate the ability to read/write data, which makes
		// forward-progress impossible. Thus, throttling this function is
		// -- at this moment -- not the solution. Either spdystream must
		// change, or we must throttle another way. go-peerstream handles
		// every new stream in its own goroutine.
		err := s.SendReply(http.Header{
			":status": []string{"200"},
		}, false)
		if err != nil {
			// this _could_ error out. not sure how to handle this failure.
			// don't return, and let the caller handle a broken stream.
			// better than _hiding_ an error.
			// return
		}
		c.streamQueue <- s
	})
}

type sshMuxTransport struct{
	serverConfig *ssh.ServerConfig

}

const version = "SSH-2.0-dmesh"

// NewWsSshTransport creates a new transport using Websocket and SSH
// Based on QUIC transport.
//
func NewWsSshTransport(key ic.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater) (*sshMuxTransport, error) {
	return &sshMuxTransport{
		serverConfig: &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return nil, fmt.Errorf("password rejected for %q", c.User())
			},
			ServerVersion: version,
			//PublicKeyCallback: sshGate.authPub,
			Config: ssh.Config{
				MACs: []string{"none", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256", "hmac-sha1", "hmac-sha1-96"},
				Ciphers: []string{
					"aes128-gcm@openssh.com",
					"chacha20-poly1305@openssh.com",
					"aes128-ctr", "none",
				},
			},
		},
	}, nil
}

// Transport is a go-peerstream spdyMuxTransport that constructs
// spdystream-backed connections.
var SSHMuxTransport = sshMuxTransport{}

func (t sshMuxTransport) NewConn(nc net.Conn, isServer bool) (transport.CapableConn, error) {
	if isServer {
		conn, chans, globalSrvReqs, err := ssh.NewServerConn(nc, &ssh.ServerConfig{

		})
		sc, err := spdystream.NewConnection(nc, isServer)
		if err != nil {
			return nil, err
		}
		c := &sshconn{
			sc:     sc,
			wsCon:  nc,
			closed: make(chan struct{}),
		}
		c.streamQueue = make(chan ssh.Channel, 10)
		go c.serve()
		return c, nil

	} else {
		cc, chans, reqs, err := ssh.NewClientConn(nc, "", &ssh.ClientConfig{
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				return nil
			},
		})
		if err != nil {
			return nil, err
		}
		client := ssh.NewClient(cc, chans, reqs)
		c := &sshconn {
			scl: client,
			closed: make(chan struct{}),
		}
		c.streamQueue = make(chan ssh.Channel, 10)
		return c, nil
	}

}

