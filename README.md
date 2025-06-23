
# Folder synchronisation tool

## Overview

This is a C# console application that synchronizes two folders: a source and a replica. The replica folder is maintained as a complete and identical copy of the source folder. Synchronization is one-way and happens at regular intervals.

All file creation, modification, and deletion operations are logged both to a file and to the console output.

This project is developed as a test task for a technical assessment.

## Features

- **One-way synchronization**: replica folder always matches source folder
- **Periodic synchronization** with configurable interval
- **File change detection** using SHA-256 hash comparison
- **Recursive directory synchronization**, including subfolders
- **Disk space check** before copying files
- **Logging** to console and specified file
- **Graceful shutdown** with `Ctrl + S`
- **User input validation** with permission checks


## Run


When started, the program prompts for:

    1) Source folder path (must point to an existing readable directory)

    2) Replica (target) folder path (must point to an existing writable directory)

    3) Synchronization interval (in seconds, must be ≥ 1)

    4) Log file path (must point to an existing writable directory)


Once running, the synchronization process:

- Copies new or modified files to the replica folder.

- Deletes files or folders in the replica that do not exist in the source.

- Logs all operations.


## Example

```
Enter source folder: C:\Users\Documents\Source
Enter target folder: D:\Backup\Replica
Enter synchronisation interval in seconds: 10
Enter log filepath: C:\Logs\sync_log.txt

Starting synchronization of D:\Backup\Replica with C:\Users\Documents\Source every 10 seconds...
Log file: C:\Logs\sync_log.txt
Press "ctrl + s" to stop the program.
```