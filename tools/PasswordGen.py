import argparse
import secrets
import string
import sys
from typing import Optional
from rich.console import Console
from rich.prompt import Prompt
from rich.markup import escape

MAX_PASSWORD_LENGTH = 1000
DEFAULT_PASSWORD_LENGTH = 12

def get_password_length(console: Console) -> Optional[int]:
    """Prompts for and validates the password length."""
    while True:
        try:
            length = Prompt.ask(
                "[bold bright_yellow]Enter the desired password length[/bold bright_yellow]",
                default=str(DEFAULT_PASSWORD_LENGTH),
                show_default=True,
            )
            password_length = int(length)

            if password_length <= 0:
                console.print(
                    "[bold bright_red]Password length must be a positive number.[/bold bright_red]"
                )
            elif password_length > MAX_PASSWORD_LENGTH:
                console.print(
                    f"[bold bright_red]Password length cannot exceed {MAX_PASSWORD_LENGTH} characters.[/bold bright_red]"
                )
            else:
                return password_length

        except ValueError:
            console.print("[bold bright_red]Invalid input. Please enter a valid number.[/bold bright_red]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n\n[bold bright_magenta]Exiting password generator.[/bold bright_magenta]")
            return None

def generate_password(length: int, use_numbers: bool, use_symbols: bool) -> str:
    """Generates a cryptographically secure password based on specified criteria."""
    character_sets = [string.ascii_letters]

    if use_numbers:
        character_sets.append(string.digits)
    if use_symbols:
        character_sets.append(string.punctuation)

    characters = "".join(character_sets)
    return "".join(secrets.choice(characters) for _ in range(length))


def get_user_preferences(console: Console) -> tuple[Optional[int], bool, bool]:
    """Gets user preferences for password generation in interactive mode."""
    password_length = get_password_length(console)
    if password_length is None:
        return None, False, False

    use_numbers = (
        Prompt.ask(
            "[bold bright_cyan]Include numbers?[/bold bright_cyan]",
            choices=["y", "n"],
            default="y",
        ).lower()
        == "y"
    )

    use_symbols = (
        Prompt.ask(
            "[bold bright_cyan]Include symbols?[/bold bright_cyan]",
            choices=["y", "n"],
            default="y",
        ).lower()
        == "y"
    )

    return password_length, use_numbers, use_symbols

def main():
    """Main function to run the password generator, handling both CLI and interactive modes."""
    console = Console()

    parser = argparse.ArgumentParser(description="Generate a cryptographically secure random password.")
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        help=f"Specify the password length (default: {DEFAULT_PASSWORD_LENGTH}, max: {MAX_PASSWORD_LENGTH})",
    )
    parser.add_argument(
        "-n", "--no-numbers", action="store_true", help="Do not include numbers in the password"
    )
    parser.add_argument(
        "-s", "--no-symbols", action="store_true", help="Do not include symbols in the password"
    )
    
    args = parser.parse_args()
    interactive_mode = not any([args.length, args.no_numbers, args.no_symbols])

    if interactive_mode:
        password_length, use_numbers, use_symbols = get_user_preferences(console)
        if password_length is None:
            return
    else:
        password_length = (
            args.length if args.length is not None else DEFAULT_PASSWORD_LENGTH
        )
        if not (0 < password_length <= MAX_PASSWORD_LENGTH):
            console.print(
                f"[bold bright_red]Password length must be between 1 and {MAX_PASSWORD_LENGTH}.[/bold bright_red]"
            )
            return

        use_numbers = not args.no_numbers
        use_symbols = not args.no_symbols

    password = generate_password(password_length, use_numbers, use_symbols)
    console.print(
        f"\n[bold bright_green]Generated Password:[/bold bright_green] [bold bright_white on blue]{escape(password)}[/bold bright_white on blue]"
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("An unexpected error occurred. Please try again.", file=sys.stderr)
        sys.exit(1)