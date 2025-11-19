# Assignment 3: Access Control Logging
**Authors:** Spyros Stamous, Michail Gialousis
**Student ID (AM):** 2021030090, 2021030065

---

## 1. Implementation Approach

Our solution is divided into two main components: `audit_logger.so` (a shared library logger) and `audit_monitor` (an analysis tool).

### audit_logger.so

This library uses the **`LD_PRELOAD`** mechanism to intercept standard C library calls for `fopen`, `fwrite`, and `fclose`.

* **`fopen`:**
    * Before calling the "real" `fopen`, it uses `stat()` to check if the file already exists. This allows us to distinguish between **File Creation** (`operation=0`) and **File Opening** (`operation=1`).
    * The main challenge is converting the input `path` into an **Absolute Path**. We use `realpath()`. If `realpath()` fails (typically because the file doesn't exist yet, as in `"w"` mode), we manually construct the absolute path by prepending the `getcwd()` (Current Working Directory).

* **`fwrite` & `fclose`:**
    * Since these functions receive a `FILE *stream` (not a path), we implemented a helper function (`file_path`). This function discovers the absolute path by reading the symbolic link from the kernel's virtual `/proc/self/fd/` directory.

* **Hashing & Logging:**
    * For every event, the file's **SHA-256 hash** is calculated using the OpenSSL EVP library. 
    * All required fields (UID, PID, Time (UTC), Operation, Denied Flag, Hash) are written as a single CSV line to `/tmp/access_audit.log`. 

* **Safety (Concurrency & Recursion):**
    * **Concurrency:** We use `flock(LOCK_EX)` and `flock(LOCK_UN)` to acquire an exclusive lock on the log file before every write. This prevents race conditions where two concurrent processes might corrupt the log by writing at the same time. The log file is also opened in append mode to prevent overwriting. [cite: 26]
    * **Recursion:** To prevent the logger from trying to log its own actions (which would cause an infinite loop), we check if the `filename` being opened is the `LOG_FILE` itself. If it is, we call the "real" `fopen` (found via `dlsym(RTLD_NEXT, ...)`), bypassing all logging logic.

### audit_monitor.c 

This is a command-line tool that parses the `access_audit.log` and provides two features:

* **`parser()`:** A central helper function that uses `strtok_r` to split each CSV line from the log and populate a `struct log_entry`.

* **`-s` (Suspicious Users):** 
    * To correctly count *distinct* denied files, we implemented a list-within-a-list: a main `BadUser` list (tracking each UID) and, for each user, a nested `DenFile` list (tracking unique filenames).
    * When we find a `denied_flag=1` entry, we add the filename to the user's nested list *only if it's not already there*.
    * Finally, we print any user whose `disitnct_files` count is **greater than 5**.

* **`-i <filename>` (File Activity):** 
    * First, it converts the input `<filename>` to an absolute path (using the same `realpath/getcwd` logic as the logger). This is critical, as it allows us to find the file's entries even if the file has since been deleted.
    * It iterates through the log and:
        1.  Prints all UIDs that accessed the file.
        2.  Counts `operation=2` (Write) entries for each user to report how many times they **modified** it.
        3.  Uses a separate `UniqueModification` list to track unique hashes, thereby displaying the total number of **unique modifications** that occurred. 

### test_audit.c 

This program's sole purpose is to "stress test" the logger by generating a wide variety of file operations to create a comprehensive log file.

* **Step 1:** Creates and writes to 10 new files (`file_0`...`file_9`). This tests `operation=0` (Create) and `operation=2` (Write).
* **Step 2:** Opens the 10 existing files for reading. This tests `operation=1` (Open Existing).
* **Step 3:** Performs multiple `fwrite` operations on `file_11` using several different content strings. This provides the test data for `audit_monitor -i`.
* **Steps 4 & 5:** Creates 8 files (`restrict_0`...`restrict_7`) and removes all their permissions using `chmod 000`. It then attempts to open them. This is the primary test for `audit_monitor -s`, generating multiple `denied_flag=1` entries.
* **Step 6:** Attempts to read a non-existent file (`non_existing_file.txt`), which generates another `denied_flag=1` entry. 
* **Cleanup:** At the end, it `remove()`s all files it created. This also serves as a crucial test for the monitor, forcing the `audit_monitor -i` command to rely on its `getcwd()` logic (since `realpath()` fails on a deleted file).

---



## 2. Execution Steps

To compile and run the project, follow these steps from your terminal.

### 1. Compilation
First, compile all the necessary files (the shared library and the executable):

```bash
make
```

---

## 2. Generating the Log

To test the system and generate the `access_audit.log` file, run the `test_audit` program with the `audit_logger.so` library preloaded.  
This is done using the LD_PRELOAD environment variable:

```bash
LD_PRELOAD=./audit_logger.so ./test_audit
```

This will execute the test script, which populates the log file at `/tmp/access_audit.log`.

---

## 3. Analyzing the Log

Once the log is generated, you can use the `audit_monitor` tool to analyze it.

### • To detect suspicious users:
```bash
./audit_monitor -s
```

### • To analyze a specific file's activity (e.g., `file_11`):
```bash
./audit_monitor -i file_11
```
