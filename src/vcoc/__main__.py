"""The `vcoc` command: `vcoc <action> ...` for the custodian's CLI, plus `vcoc verify` and `vcoc witness`.

With no action it opens the interactive shell. `vcoc help [action]` explains one action, `vcoc man` prints the whole
manual through a pager, `vcoc uninstall` removes the command. Also runnable as `python -m vcoc`.
"""
from __future__ import annotations

import argparse
import os
import pydoc
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from vcoc import __version__

OVERVIEW = """\
vcoc {version}: verifiable chain of custody for digital evidence files

usage: vcoc [action] [options]

  vcoc                    open the interactive shell (same as `vcoc shell`)
  vcoc help [action]      show help for one action (or this list)
  vcoc man                full manual: every action and its options, in a pager
  vcoc --version          print the version
  vcoc uninstall [--yes]  remove the vcoc command (case folders, databases and keys are not touched)

Custodian actions:
{actions}

Independent tools:
  verify                  check an exported custody log, evidence, anchor and checkpoint (vcoc help verify)
  witness                 cosign checkpoints as an independent witness (vcoc help witness)

vcoc works on the files in the current folder (vcoc.db, private_key.pem, shell_config.json), like git:
run it inside the case folder.
"""


def _subcommands(parser: argparse.ArgumentParser) -> dict[str, tuple[str, argparse.ArgumentParser]]:
    """name -> (one-line help, sub-parser), in the order the parser defines them."""
    for action in parser._actions:  # argparse has no public way to list sub-commands
        if isinstance(action, argparse._SubParsersAction):
            helps = {a.dest: a.help or "" for a in action._choices_actions}
            return {name: (helps.get(name, ""), p) for name, p in action.choices.items()}
    return {}


def _cli_parser() -> argparse.ArgumentParser:
    from vcoc import cli

    return cli.build_parser()


def overview() -> str:
    actions = "\n".join(f"  {name:<22}  {text}" for name, (text, _) in _subcommands(_cli_parser()).items())
    return OVERVIEW.format(version=__version__, actions=actions)


def _verify_help() -> str:
    """verifier.py builds its parser inside main(), so its help is captured by running it with --help."""
    import contextlib
    import io

    from vcoc import verifier

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        verifier.main(["--help"])
    return buf.getvalue()


def help_for(name: str) -> str | None:
    if name == "verify":
        return _verify_help()
    if name == "witness":
        from vcoc import witness

        parser = witness.build_parser()
        return parser.format_help() + "".join(
            f"\n--- vcoc witness {sub} ---\n{p.format_help()}" for sub, (_, p) in _subcommands(parser).items()
        )
    sub = _subcommands(_cli_parser()).get(name)
    return sub[1].format_help() if sub else None


def manual() -> str:
    names = [*_subcommands(_cli_parser()), "verify", "witness"]
    rule = "=" * 78
    return overview() + "".join(f"\n{rule}\nvcoc {name}\n{rule}\n{help_for(name)}" for name in names)


def _uninstall_command() -> list[str] | None:
    """How this copy of vcoc was installed decides how it is removed. install.ps1/install.sh use uv, which leaves a
    uv-receipt.toml in the tool's environment (and that environment has no pip); pipx keeps apps in .../pipx/venvs/<name>;
    anything else is a plain pip install. None: installed by uv, but uv is not on PATH."""
    env = Path(sys.prefix)
    if (env / "uv-receipt.toml").exists():
        uv = shutil.which("uv")
        return [uv, "tool", "uninstall", "vcoc"] if uv else None
    if env.parent.name == "venvs":
        pipx = shutil.which("pipx")
        return [pipx, "uninstall", "vcoc"] if pipx else [sys.executable, "-m", "pipx", "uninstall", "vcoc"]
    return [sys.executable, "-m", "pip", "uninstall", "-y", "vcoc"]


def _cmd_exe_line(args: list[str]) -> str | None:
    """`args` as one cmd.exe command, each one double-quoted so & | < > ^ in a path stay literal. None if an argument
    holds a character cmd.exe still acts on inside quotes (" or %)."""
    if any('"' in a or "%" in a for a in args):
        return None
    return " ".join(f'"{a}"' for a in args)


def uninstall(yes: bool) -> None:
    cmd = _uninstall_command()
    if cmd is None:
        print("vcoc was installed with uv, but uv is not on PATH. Open a new terminal and run: uv tool uninstall vcoc")
        sys.exit(1)
    if not yes:
        try:
            answer = input("Remove the vcoc command? Case folders, databases and keys are not touched. [y/N] ")
        except EOFError:  # no terminal to answer from: same as "no"; scripts pass --yes
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing removed.")
            return
    if os.name != "nt":
        os.execvp(cmd[0], cmd)  # replaces this process, so nothing of vcoc is still running
    # Windows locks the running vcoc.exe and python.exe, so they cannot be deleted now: remove them a moment after
    # this process has exited, from a detached cmd (/d: no AutoRun commands), with the output kept in a log.
    log = Path(tempfile.gettempdir()) / "vcoc-uninstall.log"
    line, log_arg = _cmd_exe_line(cmd), _cmd_exe_line([str(log)])
    if line is None or log_arg is None:
        print(f"Cannot run the removal safely through cmd.exe. Close vcoc and run: {subprocess.list2cmdline(cmd)}")
        sys.exit(1)
    subprocess.Popen(
        f'cmd /d /c "timeout /t 2 /nobreak >nul & {line} > {log_arg} 2>&1"',
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )
    print(f"vcoc will be removed in a few seconds (log: {log}). Open a new terminal afterwards.")


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv:
        argv = ["shell"]
    first = argv[0]
    if first in ("--version", "-V"):
        print(f"vcoc {__version__}")
    elif first in ("help", "-h", "--help"):
        if len(argv) == 1:
            print(overview(), end="")
            return
        text = help_for(argv[1])
        if text is None:
            print(f"vcoc: no action named {argv[1]!r}. Run `vcoc help` for the list.", file=sys.stderr)
            sys.exit(2)
        print(text, end="")
    elif first == "man":
        text = manual()
        if sys.stdout.isatty():
            pydoc.pager(text)
        else:
            print(text, end="")
    elif first == "uninstall":
        uninstall(yes=any(a in ("-y", "--yes") for a in argv[1:]))
    elif first == "verify":
        from vcoc import verifier

        verifier.main(argv[1:])
    elif first == "witness":
        from vcoc import witness

        witness.main(argv[1:])
    else:
        from vcoc import cli

        cli.main(argv)


if __name__ == "__main__":
    main()
