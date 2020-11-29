package sshtransport

import (
	"context"
	"net/http"

	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	"github.com/libp2p/go-libp2p-core/transport"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"golang.org/x/crypto/ssh"
)

// WsFmt is multiaddr formatter for WsProtocol
var WsFmt = mafmt.And(mafmt.TCP, mafmt.Base(ma.P_WS))

// WsCodec is the multiaddr-net codec definition for the websocket transport
var WsCodec = &manet.NetCodec{
	NetAddrNetworks:  []string{"wssh"},
	ProtocolName:     "wssh",
	ConvertMultiaddr: ConvertWebsocketMultiaddrToNetAddr,
	ParseNetAddr:     ParseWebsocketNetAddr,
}

// This is _not_ WsFmt because we want the transport to stick to dialing fully
// resolved addresses.
var dialMatcher = mafmt.And(mafmt.IP, mafmt.Base(ma.P_TCP), mafmt.Base(ma.P_WS))

const P_SSH = 0x11DE

func init() {
	manet.RegisterNetCodec(WsCodec)
	ma.AddProtocol(ma.Protocol{
		Name:  "wssh",
		Code:  P_SSH,
		VCode: ma.CodeToVarint(P_SSH),
	})
}

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

func (t *SSHTransport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (transport.CapableConn, error) {
	return t.maDial(ctx, raddr)
}
