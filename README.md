# Outbound

Client protocol chains for dae, using `net.Conn`, `net.PacketConn`, `DialContext`
and `ListenPacket`.

Protocols: Shadowsocks (AEAD, 2022 and stream ciphers), SSR, VMess AEAD,
VLESS/Vision, Trojan, SOCKS5, HTTP, AnyTLS, TUIC, Juicity and Hysteria2.
Transports: TLS/uTLS/REALITY, WebSocket, gRPC/Gun, HTTPUpgrade, Meek,
simple-obfs and client multiplexing.

Handshakes send the initial request before handoff; cancellation closes the
unfinished tunnel. Reusable sessions own allocation, dependencies and shutdown.
Stream errors do not imply shared carrier failure; recovery never replays data.

HTTP proxies use CONNECT; HTTP transport mode uses PUT. VMess requires
`alterId=0` and supports AES-GCM or ChaCha20-Poly1305 body encryption.

Tests use local wire peers and real TLS/HTTP2/gRPC/QUIC implementations. Run from
the dae checkout with its outbound and quic-go replacements:

```sh
nix-shell --run 'go test -race github.com/daeuniverse/outbound/... -count=1'
```
