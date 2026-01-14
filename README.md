# Network Health Checker

A Python script to perform basic network health checks on a list of IP addresses or hostnames. It runs `ping` and `traceroute` for each target and saves the results to individual output files.

## Features

- **Concurrent Checks:** Uses multithreading to check multiple hosts simultaneously.
- **Cross-Platform:** Automatically adjusts `ping` commands for macOS (Darwin) systems vs. Linux.
- **Logging:** Tracks execution and results in a `logs.txt` file.
- **Detailed Output:** Saves separate reports for each IP/hostname containing both ping and traceroute results.

## Requirements

- Python 3.x
- `ping` and `traceroute` utilities (usually available by default on Unix-like systems).

## Usage

1.  **Prepare your list of targets:**
    Create a text file (default is `ips.txt`) and list the IP addresses or hostnames you want to check, one per line.

    Example `ips.txt`:
    ```text
    8.8.8.8
    google.com
    1.1.1.1
    ```

2.  **Run the script:**
    
    To run with the default `ips.txt` input:
    ```bash
    python3 net-hc.py
    ```

    To specify a custom input file:
    ```bash
    python3 net-hc.py my_hosts_list.txt
    ```

## Output

- Results are saved in the `outputs/` directory.
- Each target will have its own file (e.g., `outputs/google.com.txt`).
- A log of the operation is saved to `outputs/logs.txt`.
