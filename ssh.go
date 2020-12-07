package wstransport

import (
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"

	"time"

	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	crypto_pb "github.com/libp2p/go-libp2p-core/crypto/pb"
	"github.com/libp2p/go-libp2p-core/mux"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	"golang.org/x/crypto/ssh"
)


// errClosed is returned when trying to accept a stream from a closed connection
var errClosed = errors.New("conn closed")
const sshVersion = "SSH-2.0-dmesh"



func PrivKey2SSH(key ic.PrivKey) (ssh.Signer, error) {
	keyB, _ := key.Raw()

	switch key.Type() {
	case crypto_pb.KeyType_Ed25519:
		ed := ed25519.PrivateKey(keyB)
		signer, err := ssh.NewSignerFromKey(ed) // ssh.Signer
		if err != nil {
			return nil, err
		}
		return signer, nil
	case crypto_pb.KeyType_RSA:
		// RSA: bytes is the DER form
		rsa, err := x509.ParsePKCS1PrivateKey(keyB)
		if err != nil {
			return nil, err
		}
			signer, _ := ssh.NewSignerFromKey(rsa)
			return signer, nil

	case crypto_pb.KeyType_ECDSA:
		ed, err := x509.ParseECPrivateKey(keyB)
		if err != nil {
			return nil, err
		}
			signer, _ := ssh.NewSignerFromKey(ed)
			return signer, nil

	//case crypto_pb.KeyType_Secp256k1:
		// Not supported
	}

	return nil, errors.New("Unsupported")
}

// NewWsSshTransport creates a new transport using Websocket and SSH
// Based on QUIC transport.
//
func NewSSHTransport(key ic.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater) (*SSHTransport, error) {
	signer, err := PrivKey2SSH(key)
	if err != nil {
		return nil, err
	}

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

// SSH transport implements the Multiplexer interface, can be used with other transports.
// The result is also a CapableConn, so no need for the extra security.
func (t *SSHTransport) NewConn(nc net.Conn, isServer bool) (mux.MuxedConn, error) {
	return t.NewCapableConn(nc, isServer)
}

// NewConn wraps a net.Conn using SSH for MUX and security.
func (t *SSHTransport) NewCapableConn(nc net.Conn, isServer bool) (transport.CapableConn, error) {
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
		// The client adds "forwarded-tcpip" and "forwarded-streamlocal" when ListenTCP is called.
		// This in turns sends "tcpip-forward" command, with IP:port
		// The method returns a Listener, with port set.
		rawCh := client.HandleChannelOpen("raw")
		go func() {
			for inCh := range rawCh {
				log.Println("RAW CHAN", inCh)

			}
		}()
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

