# Network Connection Monitor

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A Windows GUI application to monitor network connections of specific processes in real-time. Track which remote hosts your applications connect to with automatic hostname resolution using multiple DNS sources.

![Screenshot](assets/screenshot.png)

## Features

- 🔍 **Process Monitoring** - Monitor by process name (e.g., `chrome.exe`) or PID
- 🌐 **Smart Hostname Resolution** - Uses multiple DNS sources (Google, Cloudflare, Quad9, OpenDNS)
- 📊 **Real-time Updates** - Live connection tracking with automatic refresh
- 🔄 **Auto PID Refresh** - Automatically detects new instances of monitored processes
- 📋 **Clean Interface** - Professional Tkinter-based GUI with sortable table
- 💻 **CLI Support** - Command-line interface for terminal users

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows OS (uses Windows-specific process APIs)

### From Source

1. Clone the repository:
```bash
git clone https://github.com/yourusername/network-connection-monitor.git
cd network-connection-monitor
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python run.py
```

### Pre-built Executable

Download the latest release from the [Releases](https://github.com/yourusername/network-connection-monitor/releases) page.

## Usage

### GUI Application

1. Run the application (as Administrator for full access):
```bash
python run.py
```

2. Enter a process name (e.g., `chrome.exe`, `discord.exe`) or PID
3. Click "Start Monitoring"
4. View real-time connection information in the table

### Command Line Interface

```bash
# Monitor by process name
python -m src.cli chrome.exe

# Monitor by PID
python -m src.cli 1234

# Custom polling interval
python -m src.cli discord.exe --interval 1.0
```

## Building from Source

To create a standalone executable:

```bash
# Install PyInstaller
pip install pyinstaller

# Build the executable
python build.py
```

The executable will be created in the `dist/` folder.

## Project Structure

```
network-connection-monitor/
├── src/
│   ├── __init__.py      # Package initialization
│   ├── app.py           # Main GUI application
│   └── cli.py           # Command-line interface
├── assets/
│   └── icon.ico         # Application icon (optional)
├── dist/                # Built executables (generated)
├── build/               # Build artifacts (generated)
├── run.py               # Application entry point
├── build.py             # Build script for creating .exe
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── LICENSE              # MIT License
└── .gitignore           # Git ignore rules
```

## Requirements

- `psutil` - Process and system utilities
- `dnspython` - Advanced DNS resolution

## Administrator Privileges

For full functionality, run the application as Administrator. This allows access to network connections of all processes. Without admin rights, you may only see connections for processes owned by the current user.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [psutil](https://github.com/giampaolo/psutil) - Cross-platform process utilities
- [dnspython](https://www.dnspython.org/) - DNS toolkit for Python
