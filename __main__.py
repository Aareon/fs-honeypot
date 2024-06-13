import os
import sys
import subprocess
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
import toml
from loguru import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from ntfy.backends.ntfy_sh import notify
import platform
import ctypes

if platform.platform().startswith("Windows"):
    try:
        import pylnk3
        pylnk3_available = True
    except ImportError:
        pylnk3_available = False
else:
    pylnk3_available = False


CONFIG_FILE = "config.toml"


def load_config():
    with open(CONFIG_FILE, "r") as file:
        return toml.load(file)


def validate_config(config):
    required_fields = ["honeypot_files", "monitor_directory", "network_interface", "notification_debounce_seconds", "reenable_network_delay", "trigger_actions"]
    for field in required_fields:
        if field not in config:
            logger.error(f"Missing required configuration field: {field}")
            sys.exit(1)
    logger.info("Configuration validated successfully.")

config = load_config()
validate_config(config)
HONEYPOT_FILES = [Path(file).expanduser().resolve() for file in config['honeypot_files']]
MONITOR_DIRECTORY = Path(config['monitor_directory']).expanduser().resolve()
NETWORK_INTERFACE = config['network_interface']
NOTIFICATION_DEBOUNCE_SECONDS = config['notification_debounce_seconds']
REENABLE_NETWORK_DELAY = config['reenable_network_delay']
TRIGGER_ACTIONS = config['trigger_actions']

# Dictionary to keep track of the last notification time for each file
last_notification_time = defaultdict(lambda: datetime.min)

def check_elevated():
    try:
        if platform.platform().startswith("Windows"):
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux
            if os.geteuid() != 0:
                logger.error("This script must be run as root.")
                sys.exit(1)
            else:
                logger.info("Script is running with elevated permissions.")
    except Exception as e:
        logger.error(f"Failed to check for elevated permissions: {e}")
        sys.exit(1)


def parse_logged_in_users(output):
    """
    Parse the output from the `query user` command or similar and return a list of dictionaries.

    Each dictionary contains the SESSIONNAME, USERNAME, ID, STATE, TYPE, and DEVICE information.
    """
    users = []

    # Split the output into lines and iterate through them
    lines = output.strip().splitlines()

    # Extract the header for identifying column positions
    header = lines[0]
    columns = [
        header.index("SESSIONNAME"),
        header.index("USERNAME"),
        header.index("ID"),
        header.index("STATE"),
        header.index("TYPE"),
        header.index("DEVICE")
    ]

    # Process each line after the header
    for line in lines[1:]:
        session_name = line[columns[0]:columns[1]].strip()
        username = line[columns[1]:columns[2]].strip()
        id_ = line[columns[2]:columns[3]].strip()
        state = line[columns[3]:columns[4]].strip()
        type_ = line[columns[4]:columns[5]].strip()
        device = line[columns[5]:].strip()

        # Add the parsed data to the users list
        users.append({
            'SESSIONNAME': session_name,
            'USERNAME': username,
            'ID': id_,
            'STATE': state,
            'TYPE': type_,
            'DEVICE': device,
        })

    return users


def get_logged_in_users():
    try:
        if platform.platform().startswith("Windows"):
            process = subprocess.Popen(["qwinsta"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            _ = process.wait()
            result = process.stdout.read().decode("utf-8")
            users = ' '.join(u['USERNAME'] for u in parse_logged_in_users(result)).strip()
            return users
        else:  # Linux
            result = subprocess.run(['w'], capture_output=True, text=True, check=True)
            return result.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get logged in users: {e}")
        return ""

def disable_network_interface(interface):
    try:
        if platform.platform().startswith("Windows"):
            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'admin=disable'], check=True)
        else:  # Linux
            subprocess.run(['ifconfig', interface, 'down'], check=True)
        logger.info(f"Network interface {interface} disabled.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to disable network interface {interface}: {e}")

def enable_network_interface(interface):
    try:
        if platform.platform().startswith("Windows"):
            subprocess.run(['netsh', 'interface', 'set', 'interface', interface, 'admin=enable'], check=True)
        else:  # Linux
            subprocess.run(['ifconfig', interface, 'up'], check=True)
        logger.info(f"Network interface {interface} enabled.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to enable network interface {interface}: {e}")

def log_off_session():
    try:
        if platform.platform().startswith("Windows"):
            result = subprocess.run(['query', 'session'], capture_output=True, text=True, check=True)
            for line in result.stdout.splitlines():
                if '>' in line:
                    session_id = line.split()[1]
                    subprocess.run(['logoff', session_id], check=True)
                    logger.info(f"Logged off session {session_id}")
        else:  # Linux (use `pkill` to log off users)
            subprocess.run(['pkill', '-KILL', '-u', os.getlogin()], check=True)
            logger.info(f"Logged off user {os.getlogin()}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to log off sessions: {e}")

def create_honeypot_files():
    logger.info("Creating honeypot files...")
    for file in HONEYPOT_FILES:
        if file.exists():
            logger.debug(f"File {file} exists, not overwriting.")
            continue
        file.parent.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Creating file {file}")
        try:
            file.write_text("This is a honeypot file. Accessing it will trigger an alert.")
            logger.debug(f"Wrote text to file {file}")
        except Exception as e:
            logger.error(f"Failed to create honeypot file {file}: {e}")

def send_notification(filename, event_kind=None):
    message = f"Honeypot file {'accessed' if event_kind is None else event_kind}: {filename}"
    logger.warning(message)
    try:
        notify(
            "Honeypot Alert",
            message,
            topic="aareon-honeypot",
            urgency="critical",
            timeout=0,  # Never expire
        )
        logger.debug("Sent notification via ntfy")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")


def resolve_lnk_path(lnk_path):
    try:
        with open(lnk_path, 'rb') as lnk_file:
            lnk = pylnk3.parse(lnk_file)
            return Path(lnk.path).resolve()
    except Exception as e:
        logger.error(f"Failed to resolve .lnk path: {e}")
        return None

class HoneypotEventHandler(FileSystemEventHandler):
    def handle_event(self, event):
        accessed_file = Path(event.src_path).resolve()
        
        # Resolve .lnk files to their target
        if accessed_file.suffix == ".lnk" and pylnk3_available:
            accessed_file = resolve_lnk_path(accessed_file)
            if accessed_file is None:
                return

        if accessed_file in HONEYPOT_FILES:
            # Debounce notifications: only send one if the last was more than X seconds ago
            now = datetime.now()
            if now - last_notification_time[accessed_file] > timedelta(seconds=NOTIFICATION_DEBOUNCE_SECONDS):
                logger.info(f"File accessed: {accessed_file}")
                logger.info(f"Logged in user(s): {get_logged_in_users()}")
                if "send_notification" in TRIGGER_ACTIONS:
                    send_notification(accessed_file, event.event_type)
                if "disable_network" in TRIGGER_ACTIONS:
                    disable_network_interface(NETWORK_INTERFACE)
                    time.sleep(REENABLE_NETWORK_DELAY)
                    enable_network_interface(NETWORK_INTERFACE)
                if "log_off_session" in TRIGGER_ACTIONS:
                    log_off_session()
                last_notification_time[accessed_file] = now

    def on_modified(self, event):
        if not event.is_directory:
            self.handle_event(event)

    def on_created(self, event):
        if not event.is_directory:
            self.handle_event(event)

    def on_opened(self, event):
        if not event.is_directory:
            self.handle_event(event)

def monitor_files():
    logger.debug(f"Starting to monitor directory... {MONITOR_DIRECTORY}")

    event_handler = HoneypotEventHandler()
    observer = Observer()
    observer.schedule(event_handler, path=str(MONITOR_DIRECTORY), recursive=True)
    observer.start()

    try:
        while observer.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    finally:
        observer.join()

if __name__ == "__main__":
    logger.add("honeypot.log", rotation="1 MB")
    ascii_logo = """

   __            _                                        _   
  / _|          | |                                      | |  
 | |_ ___ ______| |__   ___  _ __   ___ _   _ _ __   ___ | |_ 
 |  _/ __|______| '_ \ / _ \| '_ \ / _ \ | | | '_ \ / _ \| __|
 | | \__ \      | | | | (_) | | | |  __/ |_| | |_) | (_) | |_ 
 |_| |___/      |_| |_|\___/|_| |_|\___|\__, | .__/ \___/ \__|
                                         __/ | |              
                                        |___/|_|              

"""
    logger.info(f"{ascii_logo}")
    logger.info(f"Trigger actions: {' '.join(TRIGGER_ACTIONS) if TRIGGER_ACTIONS else 'None'}")
    check_elevated()
    create_honeypot_files()
    monitor_files()
