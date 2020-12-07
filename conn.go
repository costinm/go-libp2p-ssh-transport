package wstransport

import (
	"crypto/ed25519"
	"net"
	"time"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"golang.org/x/crypto/ssh"
)

// Conn is a connection to a remote peer,
// implements CapableConn (	MuxedConn, network.ConnSecurity, network.ConnMultiaddrs
// Transport())
//
// implements MuxedConn (OpenStream/AcceptStream, Close/IsClosed)
//
//
type SSHConn struct {
	// ServerConn - also has Permission
	sc *ssh.ServerConn
	// SSH Client - only when acting as Dial
	// few internal fields in addition to ssh.Conn:
	// - forwards
	// - channelHandlers
	scl *ssh.Client


	streamQueue chan ssh.Channel

	closed chan struct{}

	// Original con, with remote/local addr
	wsCon     net.Conn

	inChans   <-chan ssh.NewChannel
	req       <-chan *ssh.Request

	LastSeen    time.Time
	ConnectTime time.Time

	// Includes the private key of this node
	t         *SSHTransport // transport.Transport

	remotePub ssh.PublicKey

	stat network.Stat
}

func (c *SSHConn) LocalPeer() peer.ID {
	p, _ := peer.IDFromPrivateKey(c.t.Key)
	return p
}

func (c *SSHConn) LocalPrivateKey() ic.PrivKey {
	return c.t.Key
}

func (c *SSHConn) RemotePeer() peer.ID {
	p, _ := peer.IDFromPublicKey(c.RemotePublicKey())
	return p
}

func (c *SSHConn) RemotePublicKey() ic.PubKey {
	kb := c.remotePub.(ssh.CryptoPublicKey)
	pubk := kb.CryptoPublicKey()
	edk := pubk.(ed25519.PublicKey)

	//stdMarshal := c.remotePub.Marshal()
	pk, _ := ic.UnmarshalEd25519PublicKey(edk)
	return pk
}

func (c *SSHConn) LocalMultiaddr() ma.Multiaddr {
	r, _ := manet.FromNetAddr(c.wsCon.LocalAddr())
	return r
}

func (c *SSHConn) RemoteMultiaddr() ma.Multiaddr {
	r, _ := manet.FromNetAddr(c.wsCon.RemoteAddr())
	return r
}

func (c *SSHConn) Transport() transport.Transport {
	return c.t
}

// The transport can also implements directly the network.Conn

func (c *SSHConn) ID() string {
	return ""
}

func (c *SSHConn) GetStreams() []network.Stream {
	return nil
}

// Replaces/uses OpenStream used in transport MuxedStream.
func (c *SSHConn) NewStream() (network.Stream, error) {
	return nil, nil
}

// Return Stat directly - for metadata.
func (c *SSHConn) Stat() network.Stat {
	return c.stat
}


func (c *SSHConn) Close() error {
	var err error
	if c.sc != nil {
		err = c.sc.Close()
	} else {
		err = c.scl.Close()
	}
	if err != nil {
		return err
	}
	if !c.IsClosed() {
		close(c.closed)
	}
	return nil
}

func (c *SSHConn) IsClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}


// OpenStream creates a new stream.
// This uses the same channel in both directions.
func (c *SSHConn) OpenStream() (mux.MuxedStream, error) {
	if c.sc != nil {
		s, r, err := c.sc.OpenChannel("direct-tcpip", []byte{})
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(r)
		return &stream{ch: s, con: c}, nil
	} else {
		s, r, err := c.scl.OpenChannel("direct-tcpip", []byte{})
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(r)
		return &stream{ch: s, con: c}, nil
	}
}

// AcceptStream accepts a stream opened by the other side.
func (c *SSHConn) AcceptStream() (mux.MuxedStream, error) {
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

