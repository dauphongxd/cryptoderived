# CrackedCrypto - Bitcoin Wallet Generator

A high-performance Rust-based Bitcoin wallet generator that creates mnemonic phrases and derives wallet addresses using BIP32 standards.

## Features

- ✅ **Mnemonic Generation**: Generate BIP39-compliant 12-word mnemonic phrases
- ✅ **BIP32 Key Derivation**: Derive private keys using standard Bitcoin derivation paths
- ✅ **Multiple Address Types**: Generate Bech32 (P2WPKH), P2SH, and P2PKH addresses
- ✅ **GPU Acceleration Ready**: Framework prepared for GPU-accelerated key derivation
- ✅ **CLI Interface**: Easy-to-use command-line interface
- ✅ **Batch Generation**: Generate multiple wallets at once

## Installation

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Git

### Build from Source

```bash
git clone <your-repo-url>
cd crackedcrypto
cargo build --release
```

## Usage

### Basic Usage

Generate a single wallet:
```bash
cargo run
```

Generate multiple wallets:
```bash
cargo run -- --count 5
```

### Command Line Options

```bash
cargo run -- --help
```

Available options:
- `--count, -c`: Number of wallets to generate (default: 1)
- `--gpu, -g`: Enable GPU acceleration (placeholder for future implementation)
- `--verbose, -v`: Enable verbose output

### Example Output

```
BECH32 address:   bc1qcvjwexvscpktnae7xwe2fawqgnv6cewgheuy3k
P2SH address:     3Py36noMxWBokZKA6qv5vaiu5iu5Usb17Z
P2PKH address:    1BUzssG9JYhN13Z54X8QKuXqt8dJYkeZR9
mnemonic:         soup spot adjust fuel grant crawl clarify hurt carpet stick beef sustain
```

## Technical Details

### Derivation Paths

The generator uses standard Bitcoin derivation paths:
- **Bech32 (P2WPKH)**: `m/84'/0'/0'/0/0` (BIP84)
- **P2SH**: Uses wrapped SegWit (P2WPKH-in-P2SH)
- **P2PKH**: Uses legacy Bitcoin addresses

### Security Features

- Uses cryptographically secure random number generation
- Implements BIP39 mnemonic standard
- Follows BIP32 hierarchical deterministic key derivation
- All operations use the secp256k1 elliptic curve

## Development

### Running Tests

```bash
cargo test
```

### Building for Release

```bash
cargo build --release
```

The optimized binary will be in `target/release/crackedcrypto`.

## Future Enhancements

- [ ] GPU acceleration using CUDA/OpenCL
- [ ] Support for different derivation paths
- [ ] Multi-signature wallet support
- [ ] Wallet import/export functionality
- [ ] Integration with hardware wallets

## License

This project is for educational purposes. Please ensure compliance with local laws and regulations when using cryptocurrency tools.

## Disclaimer

This software is provided "as is" without warranty. Use at your own risk. Always verify generated addresses and keep mnemonic phrases secure.
