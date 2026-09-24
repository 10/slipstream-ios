# Upstream notices

Pinned revisions and local changes are described in [architecture](docs/architecture.md). The patched tun2proxy component uses the following MIT terms. Other Rust dependency versions and sources are recorded in Cargo.lock. Release packages include the active iOS dependency licenses in `/var/jb/usr/share/doc/io.github.10.slipstream/copyright`; missing crate-archive notices are supplemented under `packaging/licenses/`. The release check rejects unreviewed licenses. The upstream SOCKS feature depends on the GPL-licensed `socks5-impl` crate; the local patch replaces it with a small MIT-compatible SOCKS5 client module (`src/socks5_proto.rs`), so the distributed build supports HTTP CONNECT and SOCKS5 without GPL code. That crate remains optional upstream for the unused `udpgw` feature only.

## tun2proxy

MIT License

Copyright (c) @ssrlive, B. Blechschmidt and contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

