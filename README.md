# fs-honeypot

## Overview
**fs-honeypot** is a Python script designed to monitor specified directories for access to honeypot files and trigger actions such as sending notifications, disabling network interfaces, and logging off sessions. It is designed to run on both Windows and Linux systems.

## Features

- Monitor honeypot files: Specify a list of honeypot files to monitor for access.
- Trigger actions: Customize actions to be triggered when a honeypot file is accessed, including sending notifications, disabling network interfaces, and logging off sessions.
- Platform compatibility: Supports both Windows and Linux systems.
- Notification system: Integrates with https://ntfy.sh to send notifications.

## Prerequisites

- Python 3.6 or higher
- `loguru` library for logging
- `watchdog` library for filesystem monitoring
- `ntfy` library for notifications
- `pylnk3` library (Windows-only, for resolving Windows shortcut files)
- `toml` library for configuration file parsing

## Installation
1. Clone the repository:

```sh
git clone https://github.com/askully/fs-honeypot.git
cd fs-honeypot
```

2. Install the required dependencies

```sh
poetry install --no-root
```

2.1 (Windows) Install the extras

```sh
poetry install -E windows
```

2.2 (Linux) Install the extras

```sh
sudo apt install libdbus-1-dev
```

3. Modify the `config.toml` with the files and options you desire

```toml
honeypot_files = ["~/honeypot1.txt", "~/honeypot2.txt"]
monitor_directory = "~/"
network_interface = "eth0"
notification_debounce_seconds = 60
reenable_network_delay = 10
trigger_actions = ["send_notification", "disable_network", "log_off_session"]
```

## Configuration

The configuration file (`config.toml`) contains the following fields:

- `honeypot_files`: A list of honeypot files to monitor.
- `monitor_directory`: The directory to monitor for honeypot file access.
- `network_interface`: The network interface to disable/enable when a honeypot file is accessed (Linux only).
- `notification_debounce_seconds`: The debounce time in seconds to avoid multiple notifications for the same file access event.
- `reenable_network_delay`: The delay in seconds before re-enabling the network interface after disabling it.
- `trigger_actions`: A list of actions to trigger when a honeypot file is accessed. Possible values: send_notification, disable_network, log_off_session.

## Usage

1. Run the script with elevated permissions (required for trigger actions)

```sh
sudo poetry run python3 __main__.py
```
> Note: You might have to install `poetry` and reinstall the dependencies via `sudo poetry install --no-root` if you get an `ImportError`

2. The script will create the specified honeypot files if they do not already exist and start monitoring the specified directory for access to these files.

3. When a honeypot file is accessed, the specified actions will be triggered.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributions

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## Contact

For questions or support, please open an issue on the GitHub repository.