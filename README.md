# MiraXT

```text
 ██████   ██████  ███                      █████ █████ ███████████
░░██████ ██████  ░░░                      ░░███ ░░███ ░█░░░███░░░█
 ░███░█████░███  ████  ████████   ██████   ░░███ ███  ░   ░███  ░ 
 ░███░░███ ░███ ░░███ ░░███░░███ ░░░░░███   ░░█████       ░███    
 ░███ ░░░  ░███  ░███  ░███ ░░░   ███████    ███░███      ░███    
 ░███      ░███  ░███  ░███      ███░░███   ███ ░░███     ░███    
 █████     █████ █████ █████    ░░████████ █████ █████    █████   
░░░░░     ░░░░░ ░░░░░ ░░░░░      ░░░░░░░░ ░░░░░ ░░░░░    ░░░░░    
                                                                 Version : 0.9-3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|S|e|c|u|r|e|_|S|t|e|g|a|n|o|g|r|a|p|h|y|_|&|_|C|r|y|p|t|o|g|r|a|p|h|y|_|T|o|o|l|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**MiraXT** (Mirage + TXT) is a cross-platform command-line utility written in Go for hiding encrypted sensitive text files inside PNG cover images using authenticated **AES-256-GCM** encryption and **LSB (Least Significant Bit)** steganography.

---

## Features

- **Authenticated Encryption**: Uses AES-256-GCM with PBKDF2 key derivation (100,000 iterations and a random salt) to ensure data confidentiality and integrity.
- **LSB Steganography**: Embeds encrypted data cleanly into the least significant bits of PNG image channels.
- **Interactive or Flag-Based Passphrases**: Pass passwords directly via CLI flags or leave them out to trigger secure interactive prompts (with hidden keyboard input).
- **Cross-Platform**: Compiles easily for Linux, macOS, and Windows.

---

## Prerequisites

- Go `1.20` or higher installed.

Dependencies will be handled automatically by Go Modules:
- `golang.org/x/crypto/pbkdf2`
- `golang.org/x/term`

---

## Installation & Build

Clone the repository and build the binary:

```bash
git clone https://github.com/michijay/miraxt.git
cd miraxt
go mod tidy
go build -o miraxt cli.go
```

---

## Usage

### 1. Hiding a Secret Text File (`hide` mode)

#### Interactive Passphrase (Recommended):
Omit the `-pass` flag to securely type and confirm your passphrase interactively:

```bash
./miraxt -mode=hide -img=cover.png -out=stego.png -secret=secret.txt
```

#### Command Line Passphrase Flag:
```bash
./miraxt -mode=hide -img=cover.png -out=stego.png -secret=secret.txt -pass="Picard47"
```

---

### 2. Extracting a Secret Text File (`extract` mode)

#### Print Extracted Content to Terminal:
```bash
./miraxt -mode=extract -img=stego.png
```

#### Save Extracted Content to a File:
```bash
./miraxt -mode=extract -img=stego.png -extract-out=recovered.txt
```

---

## Command Line Flags Reference

| Flag | Description | Required | Default |
| :--- | :--- | :---: | :--- |
| `-mode` | Mode of operation: `hide` or `extract` | **Yes** | — |
| `-img` | Input PNG image path | **Yes** | — |
| `-out` | Output PNG image path (for `hide` mode) | No | `output.png` |
| `-secret` | Secret `.txt` file path to hide (for `hide` mode) | **Yes** (in `hide`) | — |
| `-extract-out` | Path to save decrypted file (for `extract` mode) | No | Console stdout |
| `-pass` | Passphrase for encryption/decryption | No | Interactive prompt |

---

## Cross-Compilation

To build executables for other platforms from Linux:

### Windows (64-bit)
```bash
GOOS=windows GOARCH=amd64 go build -o miraxt.exe main.go
```

### macOS (Apple Silicon M1/M2/M3/M4)
```bash
GOOS=darwin GOARCH=arm64 go build -o miraxt-mac-arm64 main.go
```

### macOS (Intel)
```bash
GOOS=darwin GOARCH=amd64 go build -o miraxt-mac-amd64 main.go
```

---

## Security Architecture

1. **Key Derivation**: PBKDF2 with SHA-256 (100,000 iterations, 16-byte random salt).
2. **Cipher**: AES-256 in GCM mode (12-byte random nonce).
3. **Payload Structure**: `[ 16-byte Salt ] + [ 12-byte Nonce ] + [ AES-GCM Ciphertext ]`
4. **Steganography Method**: The payload size (4 bytes) and payload bytes are distributed across the red, green, and blue (RGB) LSB channels of the PNG image pixels.

---

## License

This project is released under the **GNU General Public License v3.0**. See the [LICENSE](LICENSE) file for details.
