# PHP Filter Source Disclosure Tool

A Python utility to exploit PHP filter wrappers via LFI, extract PHP source code, and flag potential secrets.

## Features
- Discovers PHP files via `ffuf` (fast) or a built-in wordlist loop
- Builds `php://filter/read=convert.base64-encode/resource=...` payloads automatically
- Extracts and decodes base64-wrapped PHP source
- Scans extracted code for common secrets (DB creds, API keys, JWT secrets, include paths)
- Saves recovered sources and a summary report

## Requirements
- Python 3.8+
- `requests` (`pip install requests`)
- Optional: `ffuf` in PATH for faster discovery (`go install github.com/ffuf/ffuf@latest`)

## Usage
```bash
python3 main.py -u "http://target.com/index.php?page=home" -p page -w php_files.txt
```

### Arguments
- `-u, --url`      Target URL (include the vulnerable parameter)
- `-p, --param`    Vulnerable parameter name
- `-w, --wordlist` Wordlist for PHP file discovery (used with ffuf or built-in)
- `-f, --files`    Comma-separated list of specific files to test directly (bypasses discovery)
- `-o, --output`   Output directory for saved sources/report (default: `php_sources`)
- `--no-ffuf`      Use built-in discovery instead of ffuf

### Examples
- Fast discovery with ffuf:
```bash
python3 main.py -u "http://target.com/index.php?page=home" -p page -w php_files.txt
```
- Use built-in discovery (no ffuf installed):
```bash
python3 main.py -u "http://target.com/index.php?page=home" -p page -w php_files.txt --no-ffuf
```
- Test specific files directly:
```bash
python3 main.py -u "http://target.com/index.php?page=home" -p page -f config,index,admin -o results
```

## Output
- Extracted PHP files saved under the chosen output directory (e.g., `php_sources/`)
- `report.txt` summarizes files extracted and any secrets found

## How It Works
1) Discovers candidate PHP files (ffuf or built-in requests loop)
2) Crafts PHP filter payloads and requests them via the vulnerable parameter
3) Extracts base64 from responses, decodes PHP source, and verifies it contains PHP
4) Scans for secrets and saves results and a report

## Legal / Safety
Use only on targets you have permission to test. Extracted secrets may be sensitive—handle and store results securely.
