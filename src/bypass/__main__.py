import sys


def main() -> None:
    from bypass.cli import app

    SUBCOMMANDS = {"batch", "replay", "list", "--help", "-h", "--version", "-V"}
    args = sys.argv[1:]
    if args and args[0] not in SUBCOMMANDS and not args[0].startswith("-"):
        sys.argv = [sys.argv[0], "probe"] + args
    app()


if __name__ == "__main__":
    main()
