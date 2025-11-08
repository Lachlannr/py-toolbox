"""
HashTool - Cryptographic Hash Generator and Cracker

A comprehensive tool for generating and cracking cryptographic hashes with
intelligent algorithm detection, optimized performance, and enhanced security.
"""

import argparse
import hashlib
import itertools
import multiprocessing
import os
import string
import sys
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich.table import Table
from rich import box


def _build_supported_algorithms() -> Dict[str, Callable]:
    """Builds dictionary of supported hash algorithms."""
    algorithms = {}
    
    always_available = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "sha3-224": hashlib.sha3_224,
        "sha3-256": hashlib.sha3_256,
        "sha3-384": hashlib.sha3_384,
        "sha3-512": hashlib.sha3_512,
        "shake128": hashlib.shake_128,
        "shake256": hashlib.shake_256,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }
    
    algorithms.update(always_available)
    
    optional_algorithms = [
        "md4", "ripemd160", "whirlpool", "sm3", "sha512-224", "sha512-256"
    ]
    
    for algo_name in optional_algorithms:
        try:
            hashlib.new(algo_name)
            def make_hash_func(name):
                return lambda: hashlib.new(name)
            algorithms[algo_name] = make_hash_func(algo_name)
        except (ValueError, AttributeError):
            pass
    
    for variant in ["sha512_224", "sha512_256"]:
        try:
            hashlib.new(variant)
            def make_hash_func(name):
                return lambda: hashlib.new(name)
            algorithms[variant.replace("_", "-")] = make_hash_func(variant)
        except (ValueError, AttributeError):
            pass
    
    return algorithms

SUPPORTED_ALGORITHMS: Dict[str, Callable] = _build_supported_algorithms()

ALGORITHM_PRIORITY: Dict[str, int] = {
    "md5": 1,
    "md4": 2,
    "sha1": 3,
    "sha256": 4,
    "sha512": 5,
    "sha224": 6,
    "sha384": 7,
    "sha3-256": 8,
    "sha3-512": 9,
    "sha3-224": 10,
    "sha3-384": 11,
    "ripemd160": 12,
    "blake2b": 13,
    "blake2s": 14,
    "shake128": 15,
    "shake256": 16,
    "whirlpool": 17,
    "sm3": 18,
    "sha512-224": 19,
    "sha512-256": 20,
}

HASH_LENGTH_MAP: Dict[int, List[str]] = {
    32: ["md5", "md4", "shake128"],
    40: ["sha1", "ripemd160"],
    56: ["sha224", "sha3-224", "sha512-224"],
    64: ["sha256", "sha3-256", "blake2s", "shake256", "sm3"],
    96: ["sha384", "sha3-384"],
    128: ["sha512", "sha3-512", "blake2b"],
}

MAX_WORDLIST_SIZE = 200 * 1024 * 1024


def validate_hash_format(hash_value: str) -> bool:
    """Validates that hash contains only hexadecimal characters."""
    hash_value = hash_value.strip().lower()
    return all(c in '0123456789abcdef' for c in hash_value) and len(hash_value) > 0

def sanitize_input(text: str, max_length: int = 10000) -> str:
    """Sanitizes user input to prevent injection attacks."""
    if not isinstance(text, str):
        raise ValueError("Input must be a string")
    if len(text) > max_length:
        raise ValueError(f"Input too long (max {max_length} characters)")
    return text.strip()

def constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a.encode(), b.encode()):
        result |= x ^ y
    return result == 0

def get_progress_columns() -> List:
    """Returns appropriate progress columns based on platform."""
    if sys.platform == "win32":
        return [
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ]
    else:
        return [
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
        ]

def display_banner(console: Console) -> None:
    """Displays a welcome banner."""
    banner_text = (
        "[bold bright_cyan]===========================================================[/bold bright_cyan]\n"
        "[bold bright_cyan]  [bold white]HashTool - Hash Generator & Cracker[/bold white]  [/bold bright_cyan]\n"
        "[bold bright_cyan]===========================================================[/bold bright_cyan]"
    )
    console.print(banner_text)
    console.print()


def generate_hash(text: str, algorithm: str) -> str:
    """
    Generates a hash for the given text using the specified algorithm.
    
    Args:
        text: Input text to hash
        algorithm: Hash algorithm name (must be in SUPPORTED_ALGORITHMS)
        
    Returns:
        Hexadecimal hash string
        
    Raises:
        ValueError: If algorithm is not supported or input is invalid
    """
    text = sanitize_input(text)
    algorithm = algorithm.lower()
    
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    try:
        hash_func = SUPPORTED_ALGORITHMS[algorithm]
        text_bytes = text.encode('utf-8', errors='strict')
        
        if algorithm in ("shake128", "shake256"):
            hash_obj = hash_func(text_bytes)
            digest_length = 32 if algorithm == "shake128" else 64
            return hash_obj.digest(digest_length).hex()
        
        hash_obj = hash_func()
        hash_obj.update(text_bytes)
        return hash_obj.hexdigest()
    except ValueError as e:
        error_msg = str(e).lower()
        if "not available" in error_msg or "unknown" in error_msg or "unsupported" in error_msg:
            raise ValueError(
                f"Algorithm '{algorithm}' not available. "
                "It may require OpenSSL support or additional libraries."
            )
        raise

def verify_hash(text: str, hash_value: str, algorithm: str) -> bool:
    """
    Verifies if the text produces the given hash using constant-time comparison.
    
    Args:
        text: Text to verify
        hash_value: Expected hash value
        algorithm: Hash algorithm name
        
    Returns:
        True if hash matches, False otherwise
    """
    try:
        computed_hash = generate_hash(text, algorithm)
        return constant_time_compare(computed_hash.lower(), hash_value.lower().strip())
    except (ValueError, KeyError):
        return False


def _analyze_hash_patterns(hash_value: str) -> Dict[str, float]:
    """Analyzes hash patterns using statistical and heuristic analysis."""
    scores = {}
    hash_length = len(hash_value)
    
    possible = HASH_LENGTH_MAP.get(hash_length, [])
    if not possible:
        possible = list(SUPPORTED_ALGORITHMS.keys())
    
    char_distribution = {}
    for char in hash_value:
        char_distribution[char] = char_distribution.get(char, 0) + 1
    
    unique_chars = len(char_distribution)
    total_chars = len(hash_value)
    diversity = unique_chars / total_chars if total_chars > 0 else 0
    max_char_freq = max(char_distribution.values()) if char_distribution else 0
    zero_count = hash_value.count("0")
    zero_ratio = zero_count / total_chars if total_chars > 0 else 0
    
    for algo in possible:
        base_priority = ALGORITHM_PRIORITY.get(algo, 99)
        score = base_priority
        
        if hash_length == 32:
            if algo == "md5":
                score = 0.1
            elif algo == "md4":
                score = 0.2
            elif algo == "shake128":
                score = 0.3
        elif hash_length == 40:
            if algo == "sha1":
                score = 0.1
            elif algo == "ripemd160":
                score = 0.2
        elif hash_length == 64:
            if algo == "sha256":
                score = 0.1
            elif algo == "sha3-256":
                score = 0.2
            elif algo == "blake2s":
                score = 0.3
            elif algo == "shake256":
                score = 0.4
            elif algo == "sm3":
                score = 0.5
        elif hash_length == 128:
            if algo == "sha512":
                score = 0.1
            elif algo == "sha3-512":
                score = 0.2
            elif algo == "blake2b":
                score = 0.3
        
        if diversity > 0.85:
            if algo in ["sha256", "sha512", "sha1"]:
                score -= 0.05
            elif algo in ["sha3-256", "sha3-512", "blake2b", "blake2s"]:
                score += 0.05
        
        if diversity < 0.5:
            if algo in ["shake128", "shake256"]:
                score += 0.1
        
        if zero_ratio > 0.25:
            if algo in ["sha3-256", "sha3-512"]:
                score += 0.05
        
        if max_char_freq > total_chars * 0.2:
            if algo in ["shake128", "shake256"]:
                score += 0.1
        
        if hash_value[:8].count("0") >= 3:
            if algo in ["sha3-256", "sha3-512"]:
                score += 0.03
        
        scores[algo] = score
    
    return scores

def detect_possible_algorithms(hash_value: str) -> List[str]:
    """
    Detects possible hash algorithms using length, patterns, and heuristics.
    
    Args:
        hash_value: Hash string to analyze
        
    Returns:
        List of possible algorithms ordered by likelihood (most likely first)
    """
    hash_value = hash_value.strip().lower()
    
    if not validate_hash_format(hash_value):
        return []
    
    hash_length = len(hash_value)
    possible = HASH_LENGTH_MAP.get(hash_length, [])
    
    if not possible:
        possible = list(SUPPORTED_ALGORITHMS.keys())
    
    scores = _analyze_hash_patterns(hash_value)
    
    scored_algorithms = [(algo, scores.get(algo, ALGORITHM_PRIORITY.get(algo, 99))) for algo in possible]
    scored_algorithms.sort(key=lambda x: x[1])
    
    return [algo for algo, _ in scored_algorithms]


def load_wordlist(filepath: str, console: Console) -> List[str]:
    """
    Loads a wordlist from a file with security and performance optimizations.
    
    Args:
        filepath: Path to wordlist file
        console: Rich console for output
        
    Returns:
        List of passwords (empty list on error)
    """
    try:
        path = Path(filepath).resolve()
        
        if not path.exists():
            console.print(f"[bold bright_red]Error: Wordlist file '{filepath}' not found.[/bold bright_red]")
            return []
        
        if not path.is_file():
            console.print(f"[bold bright_red]Error: '{filepath}' is not a file.[/bold bright_red]")
            return []
        
        file_size = path.stat().st_size
        if file_size > MAX_WORDLIST_SIZE:
            console.print(
                f"[bold bright_red]Error: File too large ({file_size / (1024*1024):.1f}MB). "
                f"Maximum size is {MAX_WORDLIST_SIZE / (1024*1024):.0f}MB.[/bold bright_red]"
            )
            return []
        
        wordlist = []
        with Progress(
            *get_progress_columns(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Loading wordlist from '{path.name}'...",
                total=file_size
            )
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                bytes_read = 0
                for line in f:
                    line = line.strip()
                    if line:
                        wordlist.append(line)
                    bytes_read += len(line.encode('utf-8', errors='ignore'))
                    if bytes_read % 10000 == 0:
                        progress.update(task, advance=bytes_read)
        
        console.print(
            f"[bold bright_green]Loaded {len(wordlist):,} words from '{path.name}' "
            f"({file_size / (1024*1024):.2f}MB)[/bold bright_green]"
        )
        return wordlist
    
    except PermissionError:
        console.print(f"[bold bright_red]Error: Permission denied reading '{filepath}'[/bold bright_red]")
        return []
    except Exception as e:
        console.print(f"[bold bright_red]Error reading wordlist: {e}[/bold bright_red]")
        return []


def _verify_hash_worker(args: Tuple[str, str, str, int]) -> Optional[Tuple[str, int]]:
    """Worker function for multiprocessing hash verification."""
    password, hash_value, algorithm, index = args
    if verify_hash(password, hash_value, algorithm):
        return (password, index)
    return None

def dictionary_attack(
    hash_value: str,
    algorithm: str,
    console: Console,
    wordlist: List[str],
    stats: Optional[Dict] = None,
    num_workers: int = None
) -> Optional[str]:
    """
    Attempts to crack the hash using a dictionary attack with multiprocessing support.
    
    Args:
        hash_value: Hash to crack
        algorithm: Hash algorithm name
        console: Rich console for output
        wordlist: List of passwords to try
        stats: Optional dictionary to store statistics
        num_workers: Number of worker processes (None = auto-detect)
        
    Returns:
        Cracked password if found, None otherwise
    """
    if num_workers is None:
        num_workers = max(1, multiprocessing.cpu_count() - 1)
    
    console.print(f"\n[bold bright_yellow]Dictionary Attack[/bold bright_yellow]")
    console.print(f"[dim]Algorithm: {algorithm.upper()} | Workers: {num_workers}[/dim]")
    
    start_time = time.time()
    attempts = 0
    last_update = start_time
    found_password = None
    
    with Progress(
        *get_progress_columns(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Testing passwords...",
            total=len(wordlist)
        )
        
        chunksize = max(100, len(wordlist) // (num_workers * 10))
        with multiprocessing.Pool(processes=num_workers) as pool:
            work_items = [(pwd, hash_value, algorithm, i) for i, pwd in enumerate(wordlist)]
            
            try:
                for result in pool.imap_unordered(_verify_hash_worker, work_items, chunksize=chunksize):
                    attempts += 1
                    
                    if result is not None:
                        found_password = result[0]
                        pool.terminate()
                        pool.join()
                        break
                    
                    current_time = time.time()
                    if current_time - last_update >= 0.2 or attempts % 100 == 0:
                        elapsed = current_time - start_time
                        speed = attempts / elapsed if elapsed > 0 else 0
                        progress_percent = (attempts / len(wordlist) * 100) if len(wordlist) > 0 else 0
                        remaining = len(wordlist) - attempts
                        eta_seconds = (remaining / speed) if speed > 0 else 0
                        eta_minutes = int(eta_seconds // 60)
                        eta_secs = int(eta_seconds % 60)
                        
                        progress.update(
                            task,
                            advance=1,
                            description=f"[cyan]{attempts:,}/{len(wordlist):,} ({progress_percent:.1f}%) | {speed:,.0f}/s | ETA: {eta_minutes}m{eta_secs}s"
                        )
                        last_update = current_time
                    else:
                        progress.update(task, advance=1)
            except KeyboardInterrupt:
                pool.terminate()
                pool.join()
                raise
            finally:
                pass
    
    elapsed = time.time() - start_time
    if stats:
        stats.update({
            'attempts': attempts,
            'time': elapsed,
            'speed': attempts / elapsed if elapsed > 0 else 0,
        })
    
    return found_password

def brute_force_attack(
    hash_value: str,
    algorithm: str,
    max_length: int,
    charset: str,
    console: Console,
    stats: Optional[Dict] = None
) -> Optional[str]:
    """
    Attempts to crack the hash using brute force with progress tracking.
    
    Args:
        hash_value: Hash to crack
        algorithm: Hash algorithm name
        max_length: Maximum password length to try
        charset: Character set to use
        console: Rich console for output
        stats: Optional dictionary to store statistics
        
    Returns:
        Cracked password if found, None otherwise
    """
    console.print(f"\n[bold bright_yellow]Brute Force Attack[/bold bright_yellow]")
    console.print(f"[dim]Max length: {max_length}, Charset size: {len(charset)}[/dim]")
    
    total_attempts = sum(len(charset) ** i for i in range(1, max_length + 1))
    
    if total_attempts > 1_000_000:
        console.print(
            f"[bold bright_red]Warning: This will try {total_attempts:,} combinations. "
            f"This may take a while![/bold bright_red]"
        )
        confirm = Prompt.ask(
            "[bold bright_cyan]Continue?[/bold bright_cyan]",
            choices=["y", "n"],
            default="n"
        )
        if confirm.lower() != "y":
            return None
    
    start_time = time.time()
    attempts = 0
    last_update = start_time
    
    with Progress(
        *get_progress_columns(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Cracking hash...",
            total=total_attempts if total_attempts <= 1_000_000 else None
        )
        
        for length in range(1, max_length + 1):
            for attempt in itertools.product(charset, repeat=length):
                candidate = "".join(attempt)
                attempts += 1
                if verify_hash(candidate, hash_value, algorithm):
                    elapsed = time.time() - start_time
                    if stats:
                        stats.update({
                            'attempts': attempts,
                            'time': elapsed,
                            'speed': attempts / elapsed if elapsed > 0 else 0,
                        })
                    return candidate
                
                current_time = time.time()
                if current_time - last_update >= 0.5 or attempts % 1000 == 0:
                    elapsed = current_time - start_time
                    speed = attempts / elapsed if elapsed > 0 else 0
                    remaining_attempts = total_attempts - attempts if total_attempts <= 1_000_000 else None
                    if remaining_attempts and speed > 0:
                        eta_seconds = remaining_attempts / speed
                        eta_minutes = int(eta_seconds // 60)
                        eta_secs = int(eta_seconds % 60)
                        eta_str = f" | ETA: {eta_minutes}m{eta_secs}s"
                    else:
                        eta_str = ""
                    
                    progress.update(
                        task,
                        advance=1000 if attempts % 1000 == 0 else 0,
                        description=f"[cyan]Length {length}/{max_length} | {attempts:,} attempts | {speed:,.0f}/s{eta_str}"
                    )
                    last_update = current_time
    
    elapsed = time.time() - start_time
    if stats:
        stats.update({
            'attempts': attempts,
            'time': elapsed,
            'speed': attempts / elapsed if elapsed > 0 else 0,
        })
    
    return None

def crack_hash(
    hash_value: str,
    algorithm: str,
    brute_force: bool,
    max_length: int,
    console: Console,
    wordlist: List[str],
    stats: Optional[Dict] = None,
    num_workers: int = None
) -> Optional[str]:
    """
    Attempts to crack the given hash using dictionary and optionally brute force.
    
    Args:
        hash_value: Hash to crack
        algorithm: Hash algorithm name
        brute_force: Whether to enable brute force after dictionary attack
        max_length: Maximum length for brute force
        console: Rich console for output
        wordlist: List of passwords for dictionary attack
        stats: Optional dictionary to store statistics
        num_workers: Number of worker processes for multiprocessing
        
    Returns:
        Cracked password if found, None otherwise
    """
    result = dictionary_attack(hash_value, algorithm, console, wordlist, stats, num_workers)
    if result:
        return result
    
    console.print("[bold bright_red]Dictionary attack failed.[/bold bright_red]\n")
    
    if brute_force:
        charsets = [
            ("digits", string.digits),
            ("lowercase letters", string.ascii_lowercase),
            ("lowercase + digits", string.ascii_lowercase + string.digits),
            ("all printable ASCII", string.ascii_letters + string.digits + string.punctuation),
        ]
        
        for charset_name, charset in charsets:
            console.print(f"\n[bold bright_cyan]Trying {charset_name} charset...[/bold bright_cyan]")
            result = brute_force_attack(hash_value, algorithm, max_length, charset, console, stats)
            if result:
                return result
    
    return None


def hash_mode(console: Console, text: Optional[str] = None, algorithm: Optional[str] = None) -> None:
    """
    Hash generation mode with enhanced UI.
    
    Args:
        console: Rich console for output
        text: Optional text to hash (prompts if None)
        algorithm: Optional algorithm name (prompts if None)
    """
    if text is None:
        text = Prompt.ask("[bold bright_yellow]Enter text to hash[/bold bright_yellow]")
    
    text = sanitize_input(text)
    
    if algorithm is None:
        algorithm = Prompt.ask(
            "[bold bright_cyan]Select hash algorithm[/bold bright_cyan]",
            choices=list(SUPPORTED_ALGORITHMS.keys()) + ["all"],
            default="sha256"
        )
    
    console.print()
    if algorithm == "all":
        table = Table(
            title=f"[bold bright_green]All Hashes for:[/bold bright_green] [white]{text}[/white]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            expand=True
        )
        table.add_column("Algorithm", style="cyan", no_wrap=True, width=12)
        table.add_column("Hash", style="bright_white", overflow="wrap", no_wrap=False)
        
        for algo in sorted(SUPPORTED_ALGORITHMS.keys(), key=lambda x: ALGORITHM_PRIORITY.get(x, 99)):
            hash_result = generate_hash(text, algo)
            table.add_row(algo.upper(), hash_result)
        
        console.print(table)
    else:
        hash_result = generate_hash(text, algorithm)
        
        table = Table(
            title=f"[bold bright_green]Hash Result[/bold bright_green]",
            box=box.ROUNDED,
            show_header=False,
            expand=True
        )
        table.add_column("Property", style="cyan", width=15)
        table.add_column("Value", style="bright_white", overflow="fold", no_wrap=False)
        
        table.add_row("Algorithm", algorithm.upper())
        table.add_row("Input", text)
        table.add_row("Length", f"{len(hash_result)} characters")
        
        console.print(table)
        console.print(f"\n[bold bright_white]Hash:[/bold bright_white] [cyan]{hash_result}[/cyan]", overflow="fold")

def crack_mode(
    console: Console,
    hash_value: Optional[str] = None,
    algorithm: Optional[str] = None,
    brute_force: bool = False,
    max_length: int = 4,
    wordlist_file: Optional[str] = None,
    num_workers: int = None
) -> None:
    """
    Hash cracking mode with enhanced UI and statistics.
    
    Args:
        console: Rich console for output
        hash_value: Optional hash to crack (prompts if None)
        algorithm: Optional algorithm name (auto-detects if None)
        brute_force: Whether to enable brute force
        max_length: Maximum length for brute force
        wordlist_file: Path to wordlist file (required)
        num_workers: Number of worker processes for multiprocessing
    """
    if hash_value is None:
        hash_value = Prompt.ask("[bold bright_yellow]Enter hash to crack[/bold bright_yellow]")
    
    hash_value = hash_value.strip()
    
    if not validate_hash_format(hash_value):
        console.print("[bold bright_red]Error: Invalid hash format. Must be hexadecimal.[/bold bright_red]")
        return
    
    if wordlist_file is None:
        console.print(
            "[bold bright_red]Error: Wordlist file is required for cracking. "
            "Use -w/--wordlist to specify a wordlist file.[/bold bright_red]"
        )
        return
    
    wordlist = load_wordlist(wordlist_file, console)
    if not wordlist:
        console.print("[bold bright_red]No words loaded from wordlist. Cannot proceed.[/bold bright_red]")
        return
    
    stats = {'attempts': 0, 'time': 0, 'speed': 0}
    start_time = time.time()
    
    if algorithm is None:
        possible_algorithms = detect_possible_algorithms(hash_value)
        
        if not possible_algorithms:
            console.print("[bold bright_red]Error: Could not detect algorithm from hash format.[/bold bright_red]")
            return
        
        console.print(f"\n[bold bright_cyan]Auto-detected possible algorithms:[/bold bright_cyan]")
        for i, algo in enumerate(possible_algorithms, 1):
            console.print(f"  [dim]{i}. {algo.upper()}[/dim]")
        console.print(f"[dim]Trying each algorithm until we find a match...[/dim]\n")
        
        for algo in possible_algorithms:
            console.print(f"[bold bright_yellow]Trying {algo.upper()}...[/bold bright_yellow]")
            result = crack_hash(hash_value, algo, brute_force, max_length, console, wordlist, stats, num_workers)
            
            if result:
                elapsed = time.time() - start_time
                _display_success(console, result, algo, stats, elapsed)
                return
        
        elapsed = time.time() - start_time
        _display_failure(console, brute_force, elapsed)
        return
    
    console.print(f"\n[bold bright_magenta]Attempting to crack {algorithm.upper()} hash[/bold bright_magenta]")
    console.print(f"[dim]Hash: {hash_value}[/dim]\n")
    
    result = crack_hash(hash_value, algorithm, brute_force, max_length, console, wordlist, stats, num_workers)
    elapsed = time.time() - start_time
    
    if result:
        _display_success(console, result, algorithm, stats, elapsed)
    else:
        _display_failure(console, brute_force, elapsed)

def _display_success(
    console: Console,
    password: str,
    algorithm: str,
    stats: Dict,
    elapsed: float
) -> None:
    """Displays success message with statistics."""
    console.print()
    success_panel = Panel(
        f"[bold bright_green]Password Found![/bold bright_green]\n\n"
        f"[cyan]Password:[/cyan] [bold white]{password}[/bold white]\n"
        f"[cyan]Algorithm:[/cyan] {algorithm.upper()}\n"
        f"[cyan]Verification:[/cyan] {generate_hash(password, algorithm)}\n\n"
        f"[dim]Attempts: {stats.get('attempts', 0):,}[/dim]\n"
        f"[dim]Time: {elapsed:.2f}s[/dim]\n"
        f"[dim]Speed: {stats.get('speed', 0):,.0f} hashes/sec[/dim]",
        title="[bold green]Success[/bold green]",
        border_style="green",
        box=box.ROUNDED
    )
    console.print(success_panel)

def _display_failure(console: Console, brute_force: bool, elapsed: float) -> None:
    """Displays failure message with suggestions."""
    console.print()
    failure_panel = Panel(
        f"[bold bright_red]Failed to crack hash[/bold bright_red]\n\n"
        f"[dim]Time elapsed: {elapsed:.2f}s[/dim]\n\n"
        f"[yellow]Suggestions:[/yellow]\n"
        f"  • Try a different wordlist\n"
        f"  • Enable brute force with --brute-force\n"
        f"  • Increase --max-length for brute force\n"
        f"  • Specify algorithm manually with -a/--algorithm",
        title="[bold red]Failure[/bold red]",
        border_style="red",
        box=box.ROUNDED
    )
    console.print(failure_panel)


def main() -> None:
    """Main function to run the hash tool."""
    if sys.platform == "win32":
        os.environ["PYTHONIOENCODING"] = "utf-8"
    
    console = Console(force_terminal=True, legacy_windows=False)
    
    display_banner(console)
    
    parser = argparse.ArgumentParser(
        description="Generate and crack cryptographic hashes with intelligent algorithm detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate hash
  python HashTool.py hash -t "password123" -a sha256
  python HashTool.py hash -t "password123" -a all
  
  # Crack hash (auto-detect algorithm)
  python HashTool.py crack -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt
  
  # Crack hash (specify algorithm)
  python HashTool.py crack -H 5f4dcc3b5aa765d61d8327deb882cf99 -a md5 -w wordlist.txt
  
  # Crack with brute force
  python HashTool.py crack -H e10adc3949ba59abbe56e057f20f883e -a md5 -w wordlist.txt --brute-force
        """
    )
    
    subparsers = parser.add_subparsers(dest="mode", help="Operation mode")
    
    hash_parser = subparsers.add_parser("hash", help="Generate hash from text")
    hash_parser.add_argument("-t", "--text", type=str, help="Text to hash")
    hash_parser.add_argument(
        "-a", "--algorithm",
        type=str,
        choices=list(SUPPORTED_ALGORITHMS.keys()) + ["all"],
        default="sha256",
        help="Hash algorithm to use (default: sha256)"
    )
    
    crack_parser = subparsers.add_parser("crack", help="Attempt to crack a hash")
    crack_parser.add_argument("-H", "--hash", type=str, help="Hash value to crack")
    crack_parser.add_argument(
        "-a", "--algorithm",
        type=str,
        choices=list(SUPPORTED_ALGORITHMS.keys()),
        required=False,
        help="Hash algorithm (optional - will auto-detect if not specified)"
    )
    crack_parser.add_argument(
        "--brute-force",
        action="store_true",
        help="Enable brute force attack (can be slow)"
    )
    crack_parser.add_argument(
        "--max-length",
        type=int,
        default=4,
        help="Maximum length for brute force attack (default: 4)"
    )
    crack_parser.add_argument(
        "-w", "--wordlist",
        type=str,
        required=False,
        help="Path to wordlist file (one password per line) - required for cracking"
    )
    crack_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Number of worker processes for multiprocessing (default: auto-detect, uses CPU count - 1)"
    )
    
    args = parser.parse_args()
    
    try:
        if args.mode is None:
            mode = Prompt.ask(
                "[bold bright_cyan]Select mode[/bold bright_cyan]",
                choices=["hash", "crack"],
                default="hash"
            )
            
            if mode == "hash":
                hash_mode(console)
            else:
                brute_force = Prompt.ask(
                    "[bold bright_cyan]Enable brute force attack?[/bold bright_cyan]",
                    choices=["y", "n"],
                    default="n"
                ).lower() == "y"
                
                max_length = 4
                if brute_force:
                    max_length_str = Prompt.ask(
                        "[bold bright_yellow]Maximum length for brute force[/bold bright_yellow]",
                        default="4"
                    )
                    try:
                        max_length = int(max_length_str)
                        if max_length < 1 or max_length > 10:
                            console.print("[bold bright_red]Max length must be between 1 and 10[/bold bright_red]")
                            max_length = 4
                    except ValueError:
                        console.print("[bold bright_red]Invalid number, using default: 4[/bold bright_red]")
                
                crack_mode(console, brute_force=brute_force, max_length=max_length)
        
        elif args.mode == "hash":
            hash_mode(console, args.text, args.algorithm)
        
        elif args.mode == "crack":
            crack_mode(
                console,
                args.hash,
                args.algorithm,
                args.brute_force,
                args.max_length,
                args.wordlist,
                args.workers
            )
    
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Operation cancelled by user.[/bold yellow]")
        sys.exit(1)
    except ValueError as e:
        console.print(f"[bold bright_red]Error: {e}[/bold bright_red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold bright_red]An unexpected error occurred: {e}[/bold bright_red]")
        if "--debug" in sys.argv:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
