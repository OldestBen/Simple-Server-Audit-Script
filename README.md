# Server Audit Script

This PowerShell script collects various information about a server, including IP address, server roles, access methods, virtual machine status, uptime, OS version, CPU and RAM usage, drive information, shares, security software, Windows Defender status, RDP status, and recent errors from the event logs. The collected information is exported to CSV files and event logs are exported to XML files.

## Features

- Collects server IP address and checks if it's static
- Determines access methods (e.g., TeamViewer, ITSupport247, ScreenConnect)
- Checks if the server is a virtual machine
- Retrieves server uptime
- Retrieves server OS version
- Retrieves CPU and RAM usage
- Retrieves drive information and shares
- Checks for failed or predictive fail drives using iDRAC/ILO
- Counts the number of shares
- Checks for installed security software
- Checks if Windows Defender is running
- Checks if RDP is enabled
- Exports recent errors from event logs to a text file

## Prerequisites

- PowerShell 5.1 or later
- Necessary permissions to run PowerShell scripts and access system information

## Usage

1. Download the script file (`server_audit.ps1`) to your server.
2. Open a PowerShell window with administrative privileges.
3. Navigate to the directory containing the script file.
4. Run the script:
   ```powershell
   .\server_audit.ps1

    The script will create an audit folder on the desktop and export the collected information to this folder.

Output

The script generates the following output files in the audit folder on the desktop:

    server_info.csv: Contains general server information, including IP address, server roles, access methods, virtual machine status, uptime, OS version, CPU and RAM usage, share count, security software, Windows Defender status, and RDP status.
    drive_info.csv: Contains information about the server drives, including free space, used space, total size, status, and shares.
    EventLogs\*.xml: Event logs for Application, Security, and System.
    EventLogs\RecentErrors.txt: A text file with recent errors from the event logs.



##  License

This project is licensed under the MIT License - see the LICENSE file for details.
