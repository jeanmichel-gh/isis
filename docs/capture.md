# Wire capture

Build the helper with `docker build --target capture --build-context
datalink-socket=../datalink-socket --build-context bfd4r=../bfd4r -t
isis4r-capture:latest .`.
Run `isis-capture -i eth1` in a container sharing the router network namespace,
with NET_RAW and NET_ADMIN. `-r FILE` reads a classic Ethernet PCAP.

JSON lines match RouteScope's capture and packet envelope. Each packet keeps
its complete captured frame, PDU summary from the existing parser, common
header offsets, fixed-header bytes, TLV type/length/value offsets, and padding.
Nested TLV values are decoded as text by existing objects; their inner
subfield byte offsets are not yet expanded. Bad data remains visible with
errors. Non-Ethernet PCAP inputs are refused explicitly.
