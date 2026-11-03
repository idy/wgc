// Echo exchanges a message between two local WireGuard peers.
package main

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	wireguard "github.com/idy/wgc"
	"github.com/idy/wgc/transport"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	var clientKey, clientPublic, serverKey, serverPublic wireguard.Key
	if err := wireguard.GenerateKeys(&clientKey, &clientPublic); err != nil {
		return err
	}
	if err := wireguard.GenerateKeys(&serverKey, &serverPublic); err != nil {
		return err
	}

	clientSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer clientSocket.Close()
	clientAddress := clientSocket.LocalAddr().(*net.UDPAddr)
	serverSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}

	defer serverSocket.Close()
	serverAddress := serverSocket.LocalAddr().(*net.UDPAddr)

	config := func(private *wireguard.Key, public wireguard.Key, port uint16) wireguard.Config {
		return wireguard.Config{
			StaticPrivateKey: private,
			MaxPeers:         1,
			PeerConfigLookup: func(key wireguard.Key) (*wireguard.PeerConfig, error) {
				if key != public {
					return nil, nil
				}
				return &wireguard.PeerConfig{
					Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port),
				}, nil
			},
		}
	}
	client, err := wireguard.NewConn(transport.FromUDPConn(clientSocket), config(&clientKey, serverPublic, uint16(serverAddress.Port)))
	if err != nil {
		return err
	}
	defer client.Close()
	server, err := wireguard.NewConn(transport.FromUDPConn(serverSocket), config(&serverKey, clientPublic, uint16(clientAddress.Port)))
	if err != nil {
		return err
	}
	defer server.Close()

	result := make(chan error, 2)
	go func() {
		buffer := make([]byte, wireguard.MaximumDataSize)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				result <- err
				return
			}
			if n > 0 {
				if _, _, err := server.WriteTo(buffer[:n], peer.StaticPubKey()); err != nil {
					result <- err
					return
				}
			}
		}
	}()
	go func() {
		buffer := make([]byte, wireguard.MaximumDataSize)
		for {
			n, _, err := client.ReadFrom(buffer)
			if err != nil {
				result <- err
				return
			}
			if n > 0 {
				if string(buffer[:n]) != "hello, wgc" {
					result <- fmt.Errorf("unexpected echo payload")
					return
				}
				fmt.Printf("Received authenticated echo: %s\n", buffer[:n])
				result <- nil
				return
			}
		}
	}()

	// Writes are asynchronous. Retry until a reply arrives, including while the
	// first write triggers a handshake. The connection does not ensure delivery.
	retry := time.NewTicker(100 * time.Millisecond)
	defer retry.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		if _, _, err := client.WriteTo([]byte("hello, wgc"), serverPublic); err != nil {
			return err
		}
		select {
		case err := <-result:
			return err
		case <-retry.C:
		case <-deadline.C:
			return fmt.Errorf("echo timed out")
		}
	}
}
