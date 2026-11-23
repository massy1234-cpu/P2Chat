# P2Chat

> **Work in progress.** P2Chat is under active development and is not yet usable as a messenger.
> The cryptography has not been audited: do not use it for real communications.

## The idea

P2Chat is an experimental end-to-end encrypted chat focused on two goals:

- **Post-quantum security** — key agreement and signatures combine classical and post-quantum primitives (ML-KEM, ML-DSA, X25519), so conversations stay protected against future quantum attackers.
- **Metadata minimisation** — the server should learn as little as possible about who talks to whom, when, and how much. Traffic is routed over Tor, padded, mixed with dummy requests, and accounts are registered with anonymous tokens instead of personal data.

Private keys are kept in locked memory and, where available, protected by the device's hardware (Secure Enclave on macOS, TPM on Linux/Windows).

The project consists of a Go client, a Go server and a desktop UI (Tauri + React).

## Status

The networking stack, server identification, anonymous registration, login and the first steps of the key agreement are in place. Message delivery and the ratchet for ongoing conversations are still to be built.

The detailed architecture and protocol will be published when the project is released.

## Why it's taking a while 🙂

P2Chat is a work in progress, and that's on purpose. My main goal is to **learn**: getting really good at Go and understanding what's going on under the hood — cryptography, networking, memory safety. That's also why I keep the use of coding agents to a minimum: I want to write the code myself and make every architectural decision personally, even when it's slower.

On top of that, these days I'm also studying machine learning and neural networks, and I'm in my second year at the University of Milano-Bicocca, so my free time is limited. Progress comes in bursts, but the project is very much alive. Thanks for your patience, and feel free to look around!

## Building

Requires Go 1.25+.

```bash
go build ./cmd/client ./cmd/server
```
