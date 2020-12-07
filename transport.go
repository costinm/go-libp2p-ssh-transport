package wstransport

import (
	"context"
	"net/http"

	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/ssh"
)


var _ transport.Transport = (*SSHTransport)(nil)

// SSHTransport is the actual go-libp2p transport
type SSHTransport struct {
	Prefix string
	Mux    *http.ServeMux

	Gater        connmgr.ConnectionGater
	Psk          pnet.PSK
	Key          ic.PrivKey
	serverConfig *ssh.ServerConfig
	clientConfig *ssh.ClientConfig
	signer       ssh.Signer
}

func (t *SSHTransport) CanDial(a ma.Multiaddr) bool {
	return dialMatcher.Matches(a)
}

func (t *SSHTransport) Protocols() []int {
	return []int{ma.P_WS}
}

func (t *SSHTransport) Proxy() bool {
	return false
}

// Dial creates a secure multiplexed CapableConn to the peer identified by a public key,
// using an address. The ID is derived from the proto-representation of the key - either
// SHA256 or the actual key if len <= 42
func (t *SSHTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	// Implemented in one of the WS libraries. Need to find the most efficient.
	return t.maDial(ctx, raddr, p)
}

func (t *SSHTransport) Listen(a ma.Multiaddr) (transport.Listener, error) {
	malist, err := t.maListen(a)
	if err != nil {
		return nil, err
	}
	return malist, nil
}

