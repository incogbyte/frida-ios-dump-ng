# frida-ios-dump-ng

Pull a decrypted IPA from a jailbroken device and extract `.ipa` files from jailbroken iOS devices using Frida 17+. Supports metadata analysis, and IPA comparison (Work in progress).

> **Note:** This project was inspired by [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump). I created `frida-ios-dump-ng` to address stability issues, improve performance with  async techniques, and add new features like metadata analysis and diffing.
> Thanks to [AloneMonkey](https://github.com/AloneMonkey) for the inspiration and the original tool and [Frida](https://frida.re/) for the amazing framework.

## Features
- **Metadata Analysis**: Extracts Info.plist, entitlements, and provisioning profiles (`--metadata`).
- **Full Data Extraction**: Dumps not just the binary but the entire app data container (`--app-data`).
- **IPA Diff**: Compare two IPA versions to see file changes, permission updates, and entitlement differences (`--diff`).
- **Structured Logging**: Detailed logs with configurable verbosity levels (`-v`, `-vv`).

## Requirements

- Python 3.9+
- Jailbroken iOS device
- `frida-server` (tested with **Frida 17+**) running on the device
- OpenSSH (optional, but recommended for faster transfers)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/incogbyte/frida-ios-dump-ng.git
   cd frida-ios-dump-ng
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

## Usage

### Basic Extraction
Extract the decrypted IPA from a connected device via USB:

```bash
# Spawn and dump by Bundle ID (Recommended)
python3 -m frida_ios_dump_ng -U -f com.example.app -o MyApp.ipa

# Attach to a running process
python3 -m frida_ios_dump_ng -U --pid 1234
```

### Advanced Features

#### 1. Metadata Analysis (`--metadata`)
Displays detailed app information including permissions, URL schemes, and all entitlements.

```bash
python3 -m frida_ios_dump_ng -U -f com.apple.mobilenotes --metadata
```
*Output includes: Info.plist details, minimum iOS version, and a full list of entitlements.*

#### 2. Full Data Extraction (`--app-data`)
Extracts the IPA **and** the app's data container (Documents, Library, etc.). Useful for forensic analysis or backups.

```bash
python3 -m frida_ios_dump_ng -U -f com.whatsapp.WhatsApp --app-data
# Creates: WhatsApp.ipa AND WhatsApp-data/ folder
```

#### 3. Comparing IPAs (`--diff`)
Compare two IPA files to see what changed between versions. No device connection required.

```bash
python3 -m frida_ios_dump_ng --diff v1.0.ipa v1.1.ipa
```
*Reports: File size changes, added/removed files, version bumps, and permission/entitlement changes.*

#### 4. Parallel Downloads (`--workers`)
Speed up extraction by downloading multiple files at once (default is 4).

```bash
python3 -m frida_ios_dump_ng -U -f com.example.gaming --workers 8
```

#### 5. SSH Transfer (Faster)
Use SSH/SFTP for file transfer while keeping Frida over USB.

```bash
# Connect via USB for Frida, but use SSH (192.168.1.13) for data transfer
python3 -m frida_ios_dump_ng -U -f com.example.app -H 192.168.1.13 -u mobile -p alpine
```

### Logging Options

- `-v`: Verbose output (informational logs)
- `-vv`: Debug output (timestamps, file/line info)
- `-q`: Quiet mode (errors only)
- `--log-file <file>`: Save logs to a file

```bash
python3 -m frida_ios_dump_ng -U -f com.example.app -vv --log-file dump.log
```

## CLI Arguments

| Argument | Description |
|----------|-------------|
| `-f <target>` | Spawn an app (Bundle ID or Name) |
| `--pid <pid>` | Attach to a running process ID |
| `-o <path>` | Output IPA path |
| `-U` | Connect via USB |
| `-H <host>` | SSH host address |
| `--app-data` | Dump app data container (Documents, Library, etc.) |
| `--metadata` | Show Info.plist and Entitlements after dump |
| `--diff <f1> <f2>` | Compare two IPA files |
| `--workers <n>` | Number of download threads (default: 4) |
| `--no-resume` | Keep app suspended (avoids anti-jailbreak checks) |

## Troubleshooting

- **Frida attach timed out**: Use `-f` to spawn the app instead of attaching to a running one.
- **Connection refused**: Ensure `frida-server` is running on the device.
- **SSH errors**: Check if you can SSH into the device manually (`ssh mobile@IP`). If using a different port (e.g., 2222), specify it with `-P 2222`.
