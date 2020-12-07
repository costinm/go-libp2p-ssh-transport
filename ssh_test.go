package wstransport

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"testing"

	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
	tpt "github.com/libp2p/go-libp2p-core/transport"
)

const skey = "CAESQDXW7-QhEhXWdgDUg7AvhlJU2eN-2IzMoDOWl_P271npGnwf4KUMcqufSakCfFi373F8C2HqINHxWalQwk3pVrc="
const addr = "/ip4/127.0.0.1/tcp/5555/wssh"
const spub = "12D3KooWBbkYafqbHDtmCpp47aj8P16YVfUGtyBeBB1txENTYU7x"

func TestSSHTransport(t *testing.T) {
	err := runServer("5555")
	if err != nil {
		t.Fatal(err)
	}
	err = runClient(addr, spub)
	if err != nil {
		t.Fatal(err)
	}
}

func runClient(raddr string, p string) error {
	peerID, err := peer.Decode(p)
	if err != nil {
		return err
	}
	addr, err := ma.NewMultiaddr(raddr)
	if err != nil {
		return err
	}
	priv, _, err := ic.GenerateEd25519Key(rand.Reader)
	if err != nil {
		return err
	}

	t, err := NewSSHTransport(priv, nil, nil)
	if err != nil {
		return err
	}

	log.Printf("Dialing %s\n", addr.String())
	conn, err := t.Dial(context.Background(), addr, peerID)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Reverse connections from server
	go handleConn(conn)

	str, err := conn.OpenStream()
	if err != nil {
		return err
	}
	const msg = "Hello world!"
	log.Println(conn.RemotePeer().String(), conn.RemoteMultiaddr().String(),
		conn.RemotePublicKey())
	log.Printf("Sending: %s\n", msg)
	if _, err := str.Write([]byte(msg)); err != nil {
		return err
	}
	if err := str.Close(); err != nil {
		return err
	}
	data, err := ioutil.ReadAll(str)
	if err != nil {
		return err
	}
	log.Printf("Received: %s\n", data)
	return nil
}

func runServer(port string) error {
	kb, _ := base64.URLEncoding.DecodeString(skey)
	priv, _ := ic.UnmarshalPrivateKey(kb)
	//peerID, err := peer.IDFromPrivateKey(priv)

	t, err := NewSSHTransport(priv, nil, nil)
	if err != nil {
		return err
	}

	addr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%s/wssh", port))
	if err != nil {
		return err
	}

	ln, err := t.Listen(addr)
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				log.Println("Failed to accept", err)
				return
			}
			go func() {
				if err := handleConn(conn); err != nil {
					log.Printf("handling conn failed: %s", err.Error())
				}
				str, err := conn.OpenStream()
				if err != nil {
					return
				}
				const msg = "Hello world!"
				log.Println(conn.RemotePeer().String(), conn.RemoteMultiaddr().String(),
					conn.RemotePublicKey())
				log.Printf("Sending: %s\n", msg)
				if _, err := str.Write([]byte(msg)); err != nil {
					return
				}
				if err := str.Close(); err != nil {
					return
				}
				data, err := ioutil.ReadAll(str)
				if err != nil {
					return
				}
				log.Printf("Received: %s\n", data)

			}()
		}
	}()
	return nil
}

func handleConn(conn tpt.CapableConn) error {
	r, _ := conn.RemotePublicKey().Raw()

	// Extra "ACQIARIg" in base64 for ED
	log.Printf("Accepted new connection from %s (%s) b64=%s k64=%s\n", conn.RemotePeer(), conn.RemoteMultiaddr(),
		base64.URLEncoding.EncodeToString([]byte(conn.RemotePeer())),
		base64.URLEncoding.EncodeToString(r))
	log.Println(conn.RemotePeer().String(), conn.RemoteMultiaddr().String(),
		conn.RemotePublicKey())

	str, err := conn.AcceptStream()
	if err != nil {
		return err
	}
	data, err := ioutil.ReadAll(str)
	if err != nil {
		return err
	}
	log.Printf("Received: %s\n", data)
	if _, err := str.Write([]byte(data)); err != nil {
		return err
	}
	return str.Close()
}
