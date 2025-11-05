import argparse
import random
import sys
from typing import Optional, Tuple
from rich.console import Console
from rich.prompt import Prompt

DEFAULT_MIN_NUM = 1
DEFAULT_MAX_NUM = 100
DEFAULT_MAX_ATTEMPTS = 10
MAX_RANGE_SIZE = 10000

def validate_range(min_num: int, max_num: int) -> bool:
    """Validates that the range parameters are valid."""
    return min_num < max_num and (max_num - min_num) <= MAX_RANGE_SIZE

def get_guess(console: Console, min_num: int, max_num: int) -> Optional[int]:
    """Prompts the user for a number guess and handles input validation."""
    while True:
        try:
            guess_input = Prompt.ask(
                f"[bold bright_yellow]What's your guess between {min_num} and {max_num}?[/bold bright_yellow]"
            )
            guess = int(guess_input)

            if min_num <= guess <= max_num:
                return guess
            else:
                console.print(
                    f"[bold bright_red]Invalid input. Please enter a number between {min_num} and {max_num}.[/bold bright_red]"
                )

        except ValueError:
            console.print("[bold bright_red]Invalid input. Please enter a whole number.[/bold bright_red]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n\n[bold bright_magenta]Exiting game.[/bold bright_magenta]")
            return None

def play_round(
    console: Console, min_num: int, max_num: int, max_attempts: int
) -> bool:
    """Handles the logic for a single round of the number guessing game."""
    console.print(
        f"\n[bold bright_magenta]I'm thinking of a number between {min_num} and {max_num}.\n[/bold bright_magenta]"
    )
    if max_attempts > 0:
        console.print(f"[bold bright_cyan]You have a maximum of {max_attempts} attempts.[/bold bright_cyan]")

    secret_number = random.randint(min_num, max_num)
    attempts = 0

    while True:
        guess = get_guess(console, min_num, max_num)
        if guess is None:
            return False

        attempts += 1

        if guess < secret_number:
            console.print("[bold bright_red on red]Too low! Try again.[/bold bright_red on red]")
        elif guess > secret_number:
            console.print("[bold bright_red on red]Too high! Try again.[/bold bright_red on red]")
        else:
            console.print(
                f"\n[bold bright_green on green]You got it! The number was {secret_number}.[/bold bright_green on green]"
            )
            console.print(
                f"It took you {attempts} attempt{'s' if attempts != 1 else ''}."
            )
            return True

        if max_attempts > 0 and attempts >= max_attempts:
            console.print(
                f"\n[bold bright_red on red]You've run out of attempts! The number was {secret_number}.[/bold bright_red on red]"
            )
            return False

def ask_to_play_again(console: Console) -> bool:
    """Asks the user if they want to play another round."""
    play_again = Prompt.ask(
        "[bold bright_cyan]Do you want to play again? [/bold bright_cyan]",
        choices=["y", "n"],
        default="y"
    ).lower()
    return play_again == "y"

def main():
    """Main function to run the number guessing game."""
    console = Console()

    parser = argparse.ArgumentParser(description="A number guessing game with customizable difficulty.")
    parser.add_argument(
        "--min",
        type=int,
        default=DEFAULT_MIN_NUM,
        help=f"Minimum number for the guessing range (default: {DEFAULT_MIN_NUM})",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=DEFAULT_MAX_NUM,
        help=f"Maximum number for the guessing range (default: {DEFAULT_MAX_NUM})",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=DEFAULT_MAX_ATTEMPTS,
        help=f"Maximum number of attempts (default: {DEFAULT_MAX_ATTEMPTS})",
    )
    args = parser.parse_args()

    if not validate_range(args.min, args.max):
        if args.min >= args.max:
            console.print(
                "[bold bright_red]Error: The minimum number must be less than the maximum number.[/bold bright_red]"
            )
        else:
            console.print(
                f"[bold bright_red]Error: The range size cannot exceed {MAX_RANGE_SIZE}.[/bold bright_red]"
            )
        sys.exit(1)

    while True:
        if not play_round(console, args.min, args.max, args.attempts):
            break
        if not ask_to_play_again(console):
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("An unexpected error occurred. Please try again.", file=sys.stderr)
        sys.exit(1)