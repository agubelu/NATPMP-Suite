from config_module import process_command_line_params
import time


if __name__ == "__main__":
    DAEMON_START_TIME = time.time()
    process_command_line_params()
