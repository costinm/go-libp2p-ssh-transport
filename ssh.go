package sshtransport

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net"

	"time"

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
const sshVersion = "SSH-2.0-dmesh"

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
type SSHConn struct {
	// ServerConn - also has Permission
	// Client - few internal fields
	sc ssh.Conn

	streamQueue chan ssh.Channel

	closed chan struct{}

	scl *ssh.Client

	// Original con, with remote/local addr
	wsCon     net.Conn

	inChans   <-chan ssh.NewChannel
	req       <-chan *ssh.Request

	LastSeen    time.Time
	ConnectTime time.Time

	// Includes the private key of this node
	t         *SSHTransport // transport.Transport

	remotePub ssh.PublicKey
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
		return &stream{ch: s}, nil
	} else {
		s, r, err := c.scl.OpenChannel("direct-tcpip", []byte{})
		if err != nil {
			return nil, err
		}
		go ssh.DiscardRequests(r)
		return &stream{ch: s}, nil
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

// NewWsSshTransport creates a new transport using Websocket and SSH
// Based on QUIC transport.
//
func NewSSHTransport(key ic.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater) (*SSHTransport, error) {
	keyB, _ := key.Raw()
	// TODO: RSA, EC256
	ed := ed25519.PrivateKey(keyB)
	signer, _ := ssh.NewSignerFromKey(ed) // ssh.Signer

	return &SSHTransport{
		Key: key, Psk: psk, Gater: gater,

		signer: signer,
		clientConfig: &ssh.ClientConfig{
			Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				return nil
			},
			Config: ssh.Config{
				MACs: []string{
					"hmac-sha2-256-etm@openssh.com",
					"hmac-sha2-256",
					"hmac-sha1",
					"hmac-sha1-96",
				},
				Ciphers: []string{
					"aes128-gcm@openssh.com",
					"chacha20-poly1305@openssh.com",
					"aes128-ctr", "none",
				},
			},
		},
		serverConfig: &ssh.ServerConfig{
			PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
				return nil, fmt.Errorf("password rejected for %q", c.User())
			},
			ServerVersion: sshVersion,
			//PublicKeyCallback: sshGate.authPub,
			Config: ssh.Config{
				// none is not included
				MACs: []string{
					"hmac-sha2-256-etm@openssh.com",
					"hmac-sha2-256",
					"hmac-sha1",
					"hmac-sha1-96",
				},
				Ciphers: []string{
					"aes128-gcm@openssh.com",
					"chacha20-poly1305@openssh.com",
					"aes128-ctr", "none",
				},
			},
		},
	}, nil
}

// NewConn wraps a net.Conn using SSH for MUX and security.
func (t *SSHTransport) NewConn(nc net.Conn, isServer bool) (transport.CapableConn, error) {
	c := &SSHConn{
		closed: make(chan struct{}),
		t: t,
		wsCon:  nc,
	}
	c.ConnectTime = time.Now()

	c.streamQueue = make(chan ssh.Channel, 10)

	if isServer {
		sc := &ssh.ServerConfig{
			Config: t.serverConfig.Config,
			ServerVersion: sshVersion,
			PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
				c.remotePub = key
				return &ssh.Permissions{}, nil
			},
		}
		sc.AddHostKey(t.signer)
		conn, chans, globalSrvReqs, err := ssh.NewServerConn(nc, sc)
		if err != nil {
			return nil, err
		}
		c.sc =     conn
		c.inChans = chans
		c.req = globalSrvReqs
		// From handshake
	} else {
		cc, chans, reqs, err := ssh.NewClientConn(nc, "", &ssh.ClientConfig{
			Auth: t.clientConfig.Auth,
			Config: t.clientConfig.Config,
			HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
				c.remotePub = key
				return nil
			},
		})
		if err != nil {
			return nil, err
		}
		client := ssh.NewClient(cc, chans, reqs)
		c.scl = client
		c.inChans = chans
	}

	// At this point we have remotePub
	// It can be a *ssh.Certificate or ssh.CryptoPublicKey
	//

	go func() {
		for sshc := range c.inChans {
			switch sshc.ChannelType() {
			case "direct-tcpip":
				// Ignore 'ExtraData' containing Raddr, Rport, Laddr, Lport
				acc, r, _ := sshc.Accept()
				// Ignore in-band meta
				go ssh.DiscardRequests(r)
				c.streamQueue <- acc
			}
		}
	}()

	// Handle global requests - keepalive.
	// This does not support "-R" - use high level protocol
	go func() {
		for r := range c.req {
				// Global types.
			switch r.Type {
				case "keepalive@openssh.com":
					c.LastSeen = time.Now()
					//log.Println("SSHD: client keepalive", n.VIP)
					r.Reply(true, nil)

				default:
					log.Println("SSHD: unknown global REQUEST ", r.Type)
					if r.WantReply {
						log.Println(r.Type)
						r.Reply(false, nil)
					}

			}
		}
	}()

	return c, nil

}

