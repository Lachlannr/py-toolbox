# py-toolbox

This repository is a collection of Python command-line utilities for everyday tasks and entertainment. Each tool is a standalone script built with clean, reusable patterns.

## Current Tools

**[PasswordGen.py](tools/PasswordGen.py)** — Generates cryptographically secure passwords with configurable length and character sets. Supports both interactive prompts and command-line arguments for automation.

**[GuessingGame.py](tools/GuessingGame.py)** — An interactive number guessing game with customizable difficulty (range and attempt limits). Includes play-again functionality and colorful terminal feedback.

**[HashTool.py](tools/HashTool.py)** — A comprehensive cryptographic hash generator and cracker supporting multiple algorithms (MD5, SHA family, SHA3, BLAKE2, etc.). Features intelligent algorithm detection, dictionary attacks with multiprocessing, brute force capabilities, and a rich terminal interface with progress tracking. For dictionary attacks, wordlists can be found at [weakpass.com/wordlists](https://weakpass.com/wordlists) or you can use online hash lookup services like [hashes.com](https://hashes.com/en/decrypt/hash).

## Technical Highlights

- **Cryptographic security**: Uses [`secrets`](https://docs.python.org/3/library/secrets.html) module for password generation rather than `random`, ensuring passwords are suitable for security-sensitive applications
- **Dual-mode interfaces**: Tools detect whether to run in interactive or CLI mode based on argument presence
- **Rich terminal output**: Leverages [Rich](https://rich.readthedocs.io/) for formatted prompts, styled console output, progress bars, and tables
- **Type annotations**: Functions use Python type hints for clearer interfaces
- **Graceful interruption handling**: All tools catch `KeyboardInterrupt` and `EOFError` for clean exits
- **Performance optimization**: HashTool uses multiprocessing for parallel hash verification, significantly speeding up dictionary attacks
- **Intelligent algorithm detection**: HashTool can automatically detect hash algorithms based on length and pattern analysis

## Dependencies

- **[Rich](https://rich.readthedocs.io/)** >= 13.0.0 — Terminal formatting and styled output

## Scope

This is a growing collection. More tools will be added over time as standalone utilities.