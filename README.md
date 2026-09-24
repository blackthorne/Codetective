Codetective
=============
Sometimes we run into hashes and other artefacts and can't figure out where they came from or how they were generated. Codetective recognises the output format of many different algorithms, in many different possible encodings, for analysis purposes. It also infers a level of certainty for each finding based on traces of its representation.

This may be useful, for example, when you are testing systems from a security perspective and grab a password file with hashed contents from an exposed backup or a memory dump. It can also be part of a fingerprinting process, or simply a way to verify implementations of different algorithms. You can run it against network traffic captures or large source code repositories to look for interesting stuff.

Since version 0.9.2 Codetective can also go one step further and **crack** the input: it automatically tries encodings, classical ciphers and chains of them (e.g. base64 → Bacon, or base64 → ROT13) and ranks the candidates by how much they look like real text or a CTF flag.

You can use it standalone or as a plugin for the Volatility framework. The usage is similar.

Features
--------
* **Identify** hashes, encodings and secrets: Windows (LM, NTLM, SAM), Unix shadow formats, web frameworks (Django, Joomla, phpBB3, WordPress), databases (MySQL, MSSQL), SHA/MD families, CRC, UUIDs, JWTs, base64, URLs, web cookies, phone numbers, credit cards and secrets in code. Each finding comes with a certainty score (0-100).
* **Crack** encoded or enciphered text (`-c`): base64/32/85, hex, binary, Morse, URL encoding and 25+ other encodings; Caesar/ROT variants, Vigenère, Beaufort, autokey, Gronsfeld, Porta, affine, Atbash, Bacon (24 and 26 letter), rail fence, columnar/scytale transposition, XOR (all single-byte keys) and more, up to 3 layers deep, using all CPU cores.
* **Scan** files, whole directories (recursively) or standard input. Large files are processed in overlapping chunks (with mmap) so memory stays bounded.
* **Filter** results by source (`-t`), minimum certainty (`-m`) or custom validators (`-v1..-v3`).
* **Preprocess** binary structures with `struct` format strings (`-p`) and try every codec available in Python (`-g`).
* **Configure** defaults through JSON/YAML configuration files (`--config`, see `config/CONFIGURATION.md`).

Requirements
------------
Python 3.8+. No third-party packages are needed for normal use.

Quick start
-----------

Identify a hash:

	$ python3 codetective.py '79b61b093c3c063fd45f03d55493902f'

Scan a directory recursively, showing only confident findings:

	$ python3 codetective.py -r -d mypath/ -m 80

Crack a string, a file or standard input:

	$ python3 codetective.py -c 'synt{ebg13_vf_rnfl}'
	$ python3 codetective.py -c -f challenge.txt
	$ echo 'SGVsbG8gV29ybGQh' | python3 codetective.py -c -s

Always wrap strings in single quotes so your shell doesn't interpret characters such as `!`, `$` or `{}`.

Crack mode
----------
With `-c` Codetective stops trying to *identify* the input and tries to *decode* it instead. It detects the input format (hex, base64, binary, ...), tries every supported encoding and cipher with all their built-in parameters, then chains the most promising results into further layers. Every candidate is scored 0-100 on:

* dictionary word coverage, including unspaced text (`DAYONEOFEIGHTY` reads as `DAY ONE OF EIGHTY`)
* English letter frequencies (chi-squared), index of coincidence, common bigrams/trigrams
* CTF flag formats such as `flag{...}`, `CTF{...}`, `picoCTF{...}`, `HTB{...}` (big bonus)
* penalties for unprintable characters, random-looking case (`iAYguAnOR`) and repetitive garbage

Example with a two-layer puzzle (base64 of a Baconian cipher):

	$ python3 codetective.py -c -f input.txt
	Cracking 96 characters (depth 2, min score 25)...
	This can take a while at depth 3+. Use -v to see solver progress.

	Finished in 5.7s - 3 candidate(s)

	1. [72/100] input_base64 → bacon_cipher
	   decoded:  DAYONEOFEIGHTY
	   reads as: DAY ONE OF EIGHTY
	...

	$ python3 codetective.py -c 'synt{ebg13_vf_rnfl}'
	1. [100/100] rot13
	   decoded:  flag{rot13_is_easy}
	   flag:     flag{rot13_is_easy}
	...

Options:

| Option | Default | Description |
|---|---|---|
| `-c`, `-crack` | off | Decode the input (string, `-f` file or `-s` stdin) instead of identifying it |
| `-cd`, `-crack-depth` | 2 | Maximum number of chained layers (1-3). Depth 3 takes minutes rather than seconds |
| `-ct`, `-crack-top` | 5 | Number of candidates to show |
| `-cm`, `-crack-min-score` | 25 | Minimum plausibility score; lower it to see weaker candidates |
| `-cr`, `-crack-regex` | none | Regex the answer should match, e.g. `'HTB\{.*\}'`; matching candidates get a +40 boost |
| `-cc`, `-crack-cores` | all but one | Worker processes; `1` disables multiprocessing |
| `-v` | off | Show the solver's full progress output |

Tips:

* To search harder, combine a higher depth, a lower threshold and more results: `-cd 3 -cm 15 -ct 15`.
* If you know the flag format, `-cr` is usually more effective than searching deeper.
* Keyed ciphers (Vigenère, Beaufort, ...) are tried with a built-in list of ~200 common keywords, so an unusual key will not be found by brute force.
* In crack mode `-f` reads the whole file as a single ciphertext. Trailing newlines are ignored.

The crack engine lives in `crypto_toolkit.py` and can also be used as a library:

```python
from crypto_toolkit import solve_challenge

if __name__ == '__main__':  # required for multiprocessing
    results = solve_challenge(open('input.txt').read(), max_depth=2)
    for r in results[:3]:
        print(r['score'], r['method'], r['decoded'])
```

Identification mode
-------------------
Supported filters (`-t`) are: `win`, `web`, `unix`, `db`, `personal`, `crypto` and `other`. Results improve with filters: if you know the data comes from a web application, Codetective will be more confident about framework formats such as Joomla or Django.

Supported algorithms and artefacts:

* web-cookie, URL, JWT, secrets in code, uuid
* md4, md5, sha1, sha224, sha256, sha384, sha512, RipeMD320, whirlpool, CRC
* lm hash, ntlm hash, SAM(\*:ntlm), SAM(lm:\*), SAM(lm:ntlm)
* mssql2000, mssql2005, MySQL323, MySQL4+
* des-salt-unix, md5-salt-unix, apr1-salt-unix, sha256-salt-unix, sha512-salt-unix, blowfish-salt-unix
* sha256-django, sha256-salt-django, sha384-django, sha384-salt-django
* md5-wordpress, md5-phpBB3, md5-joomla1, md5-salt-joomla1, md5-joomla2, md5-salt-joomla2
* base64
* phone numbers, credit cards

### Validators
Validators filter the output. You may use up to 3 per run with `-v1`, `-v2` and `-v3`. Each validator combines a predicate, `ALL` or `HAS`, with a matching function such as `UPPER` for findings in upper case. Supported functions:

* NUMERIC
* ALPHA
* LOWER
* UPPER
* ALPHANUMERIC
* SYMBOL

For a custom validator, use the predicate `SEARCH` followed by a regular expression.

### Generator and preprocessors
With the generator option Codetective loads every codec supported by your Python environment (the `aliases` module) and applies them to find something meaningful: multiple encodings (`-g encode`), decodings (`-g decode`) or both (`-g both`). Preprocessors (`-p`) convert binary structures into strings first, using C struct format strings.

### Large files and directories
Data is broken into slices and analysed in turn so that large files don't fill memory. An overlapping window makes sure no findings are lost at slice boundaries; as a side effect you may see duplicate results. Directory mode (`-d rootPath`) looks at folders rather than files and supports recursion (`-r`). On large amounts of data, filter by minimum certainty, e.g. `-m 70`.

Examples
--------

	$ python3 codetective.py '79b61b093c3c063fd45f03d55493902f'
	Joomla v2 MD5 - hash: 79b61b093c3c063fd45f03d55493902f
	Joomla v1 MD5 - hash: 79b61b093c3c063fd45f03d55493902f
	MD4 hash: 79b61b093c3c063fd45f03d55493902f
	MD5 hash: 79b61b093c3c063fd45f03d55493902f
	base64 decoded string: ...
	LM hash: 79b61b093c3c063fd45f03d55493902f
	NTLM hash: 79b61b093c3c063fd45f03d55493902f

Filtering by source narrows the candidates down:

	$ python3 codetective.py -t win '79B61B093C3C063FD45F03D55493902F:*'
	LM hash: 79B61B093C3C063FD45F03D55493902F
	NTLM hash: 79B61B093C3C063FD45F03D55493902F
	hashes in SAM file - LM: 79B61B093C3C063FD45F03D55493902F	NTLM: not defined

`-a` adds the type, location, certainty level and score, and detection time of each finding:

	$ python3 codetective.py -a -t win '79B61B093C3C063FD45F03D55493902F:*'
	LM hash: 79B61B093C3C063FD45F03D55493902F	(lm:0:confident[80]:2026-09-24 16:43:15.054584)
	NTLM hash: 79B61B093C3C063FD45F03D55493902F	(ntlm:0:confident[80]:2026-09-24 16:43:15.054816)
	hashes in SAM file - LM: 79B61B093C3C063FD45F03D55493902F	NTLM: not defined	(SAM(lm:*):0:likely[70]:2026-09-24 16:43:15.055075)

	$ python3 codetective.py 'dGVzdGUK'
	base64 decoded string: teste

	$ python3 codetective.py -r -d mypath/ -m 80 -fp '*.txt'

Usage
-----

	usage: codetective.py [-h] [-t filters] [-a] [-v] [-m MIN_CERTAINTY]
	                      [-p PREPROCESSOR] [-g GENERATOR] [-v1 VALIDATOR1]
	                      [-v2 VALIDATOR2] [-v3 VALIDATOR3] [-r] [-f FILENAME]
	                      [-d DIRECTORY] [-fp FILE_PATTERN] [-l] [-s] [-ver]
	                      [--config CONFIG_FILE] [-c] [-cd CRACK_DEPTH]
	                      [-ct CRACK_TOP] [-cm CRACK_MIN_SCORE] [-cr CRACK_REGEX]
	                      [-cc CRACK_CORES]
	                      [string]

	a tool to identify cryptographic hashes, encodings, and other artifacts in a
	byte stream according to traces of its representation

	positional arguments:
	  string                determine algorithm used for <string> according to its
	                        data representation

	optional arguments:
	  -h, --help            show this help message and exit
	  -t filters            filter by source of your string. can be: win, web, db,
	                        unix or other
	  -a, -analyze          show more details whenever possible (expands shadow
	                        files fields,...)
	  -v, -verbose          verbose mode shows progress status (useful for large
	                        files) and time taken
	  -m MIN_CERTAINTY, -minimum-certainty MIN_CERTAINTY
	                        specify the minimum acceptable certainty level for
	                        displayed results (0 - 100)
	  -p PREPROCESSOR, --preprocessor PREPROCESSOR
	                        <struct format string> interpret bytes as packed
	                        binary data. Unpacks contents from different data and
	                        endianess types according to format strings patterns
	                        as specified on:
	                        https://docs.python.org/3/library/struct.html
	  -g GENERATOR, -generator GENERATOR
	                        find encoding/decoding algorithm that exposes
	                        interesting artifacts (choose: 'encode', 'decode',
	                        'both')
	  -v1 VALIDATOR1, -validator1 VALIDATOR1
	                        applies validator 1
	  -v2 VALIDATOR2, -validator2 VALIDATOR2
	                        applies validator 2
	  -v3 VALIDATOR3, -validator3 VALIDATOR3
	                        applies validator 3
	  -r, -recursive        sets recursive mode upon specified directory (current
	                        workdir by default). Consider using it with
	                        min_certainty option
	  -f FILENAME, -file FILENAME
	                        load a specified file
	  -d DIRECTORY, -directory DIRECTORY
	                        load a specified directory
	  -fp FILE_PATTERN, -file-pattern FILE_PATTERN
	                        specified which file pattern to be used with directory
	                        (default: '*')
	  -l, -list             lists supported algorithms
	  -s, -stdin            read data from standard input
	  -ver, -version        displays software version
	  --config CONFIG_FILE  configuration file path

	crack mode:
	  auto-decode encodings and classical ciphers (base64, hex, Caesar,
	  Vigenere, Bacon, XOR, rail fence, ...) and chains of them

	  -c, -crack, --crack   try to decode/decrypt the input (string, -f file or -s
	                        stdin) instead of identifying it
	  -cd CRACK_DEPTH, -crack-depth CRACK_DEPTH
	                        maximum number of chained layers to try (default: 2; 3
	                        is much slower)
	  -ct CRACK_TOP, -crack-top CRACK_TOP
	                        number of candidates to show (default: 5)
	  -cm CRACK_MIN_SCORE, -crack-min-score CRACK_MIN_SCORE
	                        minimum plausibility score 0-100 (default: 25)
	  -cr CRACK_REGEX, -crack-regex CRACK_REGEX
	                        regex that the answer should match, e.g. "HTB\{.*\}"
	                        (boosts matching candidates)
	  -cc CRACK_CORES, -crack-cores CRACK_CORES
	                        worker processes to use (default: all cores but one; 1
	                        = no multiprocessing)

	use filters for more accurate results. Report bugs, ideas, feedback to:
	blackthorne@ironik.org

Volatility plugin
-----------------

	$ python vol.py codetective -h
	Volatile Systems Volatility Framework 2.0
	Usage: Volatility - A memory forensics analysis platform.

	Options:
	  ...
	  -n PNAME, --pname=PNAME
	                        define target Process name
	  -p PID, --pid=PID     define target Process ID
	  -t FILTERS, --filters=FILTERS
	                        apply filters, can be: win, web, unix, db and other
	                        (default: none)
	  -u, --uuids           include UUIDS in search (default: No)

	---------------------------------
	Module Codetective
	---------------------------------
	determine the crypto/encoding algorithm used according to traces from its representation

Most relevant options are `-u` (show UUIDs, disabled by default), `-v` (verbose mode), `-t` (filters), `-p` (process ID) and `-n` (process name). If neither `-p` nor `-n` is given, all processes are searched.

	$ python vol.py codetective -n notepad -v -f JOHN-2CF071298B-20120318-024807.raw
	Volatile Systems Volatility Framework 2.0

	Found 29 tasks
	kernel mapping...
	Calculating task mappings...
	Process: notepad.exe	PPID: 1696	Pid: 1896
	...

	=> at offset Virtual: 0x8012e000  	Physical: 0x12e000    	 Size: 0x1000
	 Found md5 (likely) 	MD5 hash: 0A5AE0AB474FF954BA5FB5CC22691599
	 Found md4 (possible) 	MD4 hash: 0A5AE0AB474FF954BA5FB5CC22691599

	=> at offset Virtual: 0x8013d000  	Physical: 0x13d000    	 Size: 0x1000
	 Found md5 (likely) 	MD5 hash: 4BE2C18D9154D0240B36AEF861085FEC
	 Found md4 (possible) 	MD4 hash: 4BE2C18D9154D0240B36AEF861085FEC
	...

Testing
-------

Run the unittest suite from the project root (tests are under `tests/`):

	$ python3 tests/run_tests.py -v

Alternatively, using unittest discovery directly:

	$ python3 -m unittest discover -s tests -p 'test_*.py' -v

Notes:
- The test runner ensures the project root is on `PYTHONPATH`.
- Test data and integration samples live in `tests/test.txt`.

Changelog
---------

### Version 0.9.2
* New **crack mode** (`-c`): automatically decodes encodings and classical ciphers, including chains up to 3 layers, and ranks candidates by plausibility. Works with strings, files (`-f`) and stdin (`-s`)
* New crack options: depth (`-cd`), number of results (`-ct`), minimum score (`-cm`), expected answer regex (`-cr`) and worker processes (`-cc`)
* New crack engine (`crypto_toolkit.py`) with 45+ transformations and 25+ encodings, multi-process search and flag detection
* Plausibility scoring recognises flag formats, measures dictionary word coverage (including word segmentation of unspaced text), and penalises unprintable characters, random case and repetitive output
* Bacon cipher: 24-letter alphabet, fixed A/B-flipped variant, and word boundaries preserved when spaces separate words
* Fixed crashes and ordering issues in the solver (depth-1 crash, duplicated depth-3 results, `max_results` ignored, missing method names)

### Version 0.9.1
* Added mypy tests
* All linting, type errors and indentation consistency issues resolved

### Version 0.9.0
* Python 3 migration: updated imports, print functions, string/bytes handling
* Refactoring: split monolithic detection into focused functions; added `PatternMatcher`
* Error handling: comprehensive try/except around file IO, decoding, and processing
* Type hints & docs: pervasive typing and improved docstrings for maintainability
* Performance: compiled regexes with UNICODE/VERBOSE, quick hash pre-checks, chunked processing, mmap for large files
* Modern Python: `@dataclass` for `Finding`, `pathlib.Path`, f-strings, constants with annotations
* Testing: comprehensive unittest suite in `tests/`, sample data in `tests/test.txt`, runner at `tests/run_tests.py`
* Configuration: added support for JSON and YAML configuration files to customise default settings

### Version 0.8.2
* Added detection for JWT tokens
* Added generic secrets detection

### Version 0.8.1
Close to a complete rewrite with new features and many bug fixes. Codetective can now report the exact location of a finding, and certainty is numeric so that multiple factors with different weights can be combined. New entropy checks improve detection of cryptographic findings, and results can be limited to a minimum certainty (`-m`). Data is processed in overlapping slices to keep memory bounded, and a verbose mode shows progress. Added directory mode (`-d`, `-r`), stdin support, the `personal` filter (phone numbers, credit cards), web cookies, URLs, the generator (`-g`), preprocessors (`-p`) and validators (`-v1..-v3`).

Discussion
----------

Identification is heavily based on regular expressions, written with a mindset of rejecting as many alternatives as possible for each submitted hash/code but never rejecting valid choices. Contributions of more algorithms, tests and feedback are welcome.

Codetective infers a confidence level for each guess and can give you a preliminary analysis (`-a`). Results improve with filters (`-t`).

If you find this tool useful, you may also like [Hash Identifier](http://code.google.com/p/hash-identifier/), which works in a different way.
