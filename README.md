# Outbound

Client protocol chains for dae. Share links build layers with standard `net.Conn`,
`net.PacketConn`, `DialContext`, and `ListenPacket` interfaces.

Protocols: Shadowsocks (AEAD, 2022 and stream ciphers), SSR, VMess AEAD,
VLESS/Vision, Trojan, SOCKS5, HTTP, AnyTLS, TUIC, Juicity and Hysteria2.
Transports include TLS/uTLS/REALITY, WebSocket, gRPC/Gun, HTTPUpgrade,
Meek, simple-obfs and client multiplexing. Production server implementations
and the old connection/buffer APIs have been removed.

Per-connection handshakes finish their initial exchange before handoff; cancellation
closes the unfinished tunnel. Reusable sessions own their streams, dependencies,
allocation gates and shutdown. Stream errors do not imply that a shared carrier
is dead. Failed application data is never replayed by recovery.

HTTP proxies use CONNECT; HTTP transport mode retains PUT. VMess requires AEAD
(`alterId=0`); body ciphers are `aes-128-gcm` and `chacha20-poly1305`.
Explicit cipher selections are preserved. VMess packet-address datagrams require IP addresses; a connected
UDP dial can resolve its fixed domain destination using the caller's context.
`seed-cfb` is unsupported: the old entry incorrectly selected RC2.

Tests use local wire peers and real TLS/HTTP2/gRPC/QUIC implementations. Run from
the dae checkout with its outbound and quic-go replacements:

```sh
nix-shell --run 'go test -race github.com/daeuniverse/outbound/... -count=1'
```
