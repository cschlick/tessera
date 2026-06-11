"""
Demonstration CLI for tessera.

Usage:
    python -m tessera enroll [--out vault.json] [--threshold T] [--fast]
                             [--encrypt PATH [--container FILE]]
    python -m tessera unlock [--vault vault.json]
                             [--decrypt FILE [--dest DIR]]

Security properties:
- Answers are read with getpass (no terminal echo) and never appear in
  argv, shell history, or the environment.
- Only the MEK is written to stdout (base64, one line); all prompts and
  messages go to stderr, so `... > mek.b64` captures the secret alone.
- Unlock failure is opaque: "unlock failed", exit code 1, no detail about
  which or how many answers were wrong.
- Questions are stored in the vault file as a convenience. They are public
  but NOT authenticated by the vault's AEAD AAD (only the PublicState is), so a
  tamperer could reword them; this cannot leak the MEK.
- Caveat: Python strings holding answers cannot be reliably zeroized.

This CLI uses ExactStringProcessor for all fields (NFC + casefold
normalization, so case and Unicode form don't matter, but typos do).
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import secrets
import sys

if __package__ in (None, ""):
    # Executed directly (`python cli.py`): give ourselves package context
    # so the relative imports below work (PEP 366).
    import os

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import tessera  # noqa: F401

    __package__ = "tessera"

from .container import open_container, seal
from .errors import ContainerError
from .params import Argon2Params, Params
from .processor import ExactStringProcessor
from .state import PublicState
from .vault import enroll, unlock

FILE_VERSION = 1

# Reduced-cost Argon2id for demos. hash_len stays 64: that is a security
# invariant (bias mod P), not a cost knob.
FAST_ARGON2 = Argon2Params(opslimit=1, memlimit=8 * 1024 * 1024, hash_len=64)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _prompt_secret(prompt: str) -> str:
    # getpass writes its prompt to stderr/tty and does not echo input.
    return getpass.getpass(prompt)


def _cmd_enroll(args: argparse.Namespace) -> int:
    import os

    if args.encrypt is not None and not os.path.exists(args.encrypt):
        _err(f"error: --encrypt path does not exist: {args.encrypt}")
        return 2
    if args.container is not None and args.encrypt is None:
        _err("error: --container requires --encrypt")
        return 2

    _err("Enter your questions, one per line. Empty line to finish.")
    questions: list[str] = []
    while True:
        try:
            # input()'s own prompt would go to stdout, which is reserved for
            # the MEK; write the prompt to stderr instead.
            sys.stderr.write(f"Question {len(questions) + 1}: ")
            sys.stderr.flush()
            q = input()
        except EOFError:
            break
        if not q.strip():
            break
        questions.append(q.strip())

    M = len(questions)
    if M < 1:
        _err("error: at least one question is required")
        return 2
    # Security policy: require at least a majority of answers (t >= M/2).
    # A lower threshold would let an attacker target only the few easiest
    # answers, gutting the combined entropy of the vault.
    min_t = (M + 1) // 2
    threshold = args.threshold
    if threshold is None:
        while True:
            sys.stderr.write(
                f"How many correct answers to unlock? [{min_t}-{M}, default {M}]: "
            )
            sys.stderr.flush()
            try:
                raw = input().strip()
            except EOFError:
                raw = ""
            if not raw:
                threshold = M
                break
            try:
                threshold = int(raw)
            except ValueError:
                _err(f"Enter a number between {min_t} and {M}.")
                continue
            if min_t <= threshold <= M:
                break
            _err(f"Enter a number between {min_t} and {M} (at least half the answers).")
    elif not (min_t <= threshold <= M):
        _err(f"error: --threshold must be in [{min_t}, {M}] (at least half the answers)")
        return 2

    _err(f"\n{M} questions, any {threshold} correct answers will unlock.")
    _err("Now enter the answers (input is hidden, each asked twice).")
    answers: list[str] = []
    for i, q in enumerate(questions, start=1):
        while True:
            a1 = _prompt_secret(f"Answer {i} ({q}): ")
            a2 = _prompt_secret(f"Answer {i} (confirm): ")
            if a1 == a2:
                break
            _err("Answers did not match, try again.")
        answers.append(a1)

    params = Params(argon2=FAST_ARGON2) if args.fast else Params()
    if args.fast:
        _err("warning: --fast uses weakened Argon2id parameters (demo only)")

    mek = secrets.token_bytes(32)
    processors = [ExactStringProcessor() for _ in range(M)]

    _err(f"Enrolling ({M} Argon2id hashes, this may take a while)...")
    state = enroll(mek, answers, processors, threshold, params)

    doc = {
        "version": FILE_VERSION,
        "questions": questions,
        "vault": json.loads(state.to_json()),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    _err(f"Vault written to {args.out} (public data, safe to back up anywhere).")

    if args.encrypt is not None:
        container_path = args.container or args.encrypt.rstrip("/") + ".tsra"
        seal(mek, args.encrypt, container_path)
        _err(f"Encrypted container written to {container_path}.")
        _err("The MEK is not displayed; recover it (or decrypt the container)")
        _err("by answering the questions: tessera unlock --decrypt " + container_path)
        _err("The original at "
             f"{args.encrypt} was NOT deleted — remove it yourself if desired.")
        return 0

    _err("Generated MEK (base64) follows on stdout — store it securely, or")
    _err("discard it and recover it later by unlocking the vault:")
    print(base64.b64encode(mek).decode("ascii"))
    return 0


def _cmd_unlock(args: argparse.Namespace) -> int:
    try:
        with open(args.vault, encoding="utf-8") as f:
            doc = json.load(f)
        state = PublicState.from_json(json.dumps(doc["vault"]))
        questions = list(doc["questions"])
    except (OSError, ValueError, KeyError) as e:
        _err(f"error: cannot read vault file: {e}")
        return 2

    M = len(state.fields)
    if len(questions) != M:
        _err("error: vault file is malformed (question count mismatch)")
        return 2

    _err(f"Answer at least {state.threshold} of {M} questions correctly.")
    _err("Input is hidden. Press Enter alone to skip a question.")
    answers: list[str | None] = []
    for i, q in enumerate(questions, start=1):
        a = _prompt_secret(f"Answer {i} ({q}): ")
        answers.append(a if a else None)

    processors = [ExactStringProcessor() for _ in range(M)]
    _err(f"Unlocking ({M} Argon2id hashes, this may take a while)...")
    mek = unlock(state, answers, processors)

    if mek is None:
        # Opaque by design: no information about which answers matched.
        _err("unlock failed")
        return 1

    if args.decrypt is not None:
        try:
            names = open_container(mek, args.decrypt, args.dest)
        except ContainerError as e:
            _err(f"error: {e}")
            return 2
        _err(f"Unlock succeeded. Extracted into {args.dest}: {', '.join(names)}")
        return 0

    _err("Unlock succeeded. MEK (base64) follows on stdout:")
    print(base64.b64encode(mek).decode("ascii"))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tessera",
        description="Blinded Shamir secret-sharing vault (demonstration CLI).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_enroll = sub.add_parser("enroll", help="create a new vault around a fresh random MEK")
    p_enroll.add_argument("--out", default="vault.json", help="vault file to write (default: vault.json)")
    p_enroll.add_argument("--threshold", type=int, default=None,
                          help="answers required to unlock (default: all of them)")
    p_enroll.add_argument("--fast", action="store_true",
                          help="weakened Argon2id parameters for quick demos")
    p_enroll.add_argument("--encrypt", metavar="PATH", default=None,
                          help="also encrypt this file or folder into a container")
    p_enroll.add_argument("--container", metavar="FILE", default=None,
                          help="container file to write (default: <PATH>.tsra)")
    p_enroll.set_defaults(func=_cmd_enroll)

    p_unlock = sub.add_parser("unlock", help="recover the MEK from a vault")
    p_unlock.add_argument("--vault", default="vault.json", help="vault file to read (default: vault.json)")
    p_unlock.add_argument("--decrypt", metavar="FILE", default=None,
                          help="decrypt this container instead of printing the MEK")
    p_unlock.add_argument("--dest", metavar="DIR", default=".",
                          help="directory to extract into (default: current directory)")
    p_unlock.set_defaults(func=_cmd_unlock)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        _err("\naborted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
