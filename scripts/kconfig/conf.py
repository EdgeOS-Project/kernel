#!/usr/bin/env python3
"""EdgeOS Kconfig command-line and ncurses menuconfig frontend.

This file is original EdgeOS code licensed under MPL-2.0.  Kconfig language
evaluation and the curses interface are provided by the vendored, ISC-licensed
Kconfiglib implementation in vendor/kconfiglib/.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
VENDOR_DIR = SCRIPT_DIR / "vendor" / "kconfiglib"
sys.path.insert(0, str(VENDOR_DIR))

import kconfiglib  # noqa: E402


CONFIG_HEADER = "# Automatically generated file; DO NOT EDIT.\n"
MAKEFILE_HEADER = "# Automatically generated file; DO NOT EDIT.\n"


def _absolute(path: str) -> pathlib.Path:
    return pathlib.Path(path).expanduser().resolve()


def _new_kconfig(kconfig_path: pathlib.Path) -> kconfiglib.Kconfig:
    # Linux resolves source paths from $srctree.  Set it explicitly so all
    # commands also work when make is invoked with -C from another directory.
    os.environ["srctree"] = str(kconfig_path.parent)
    return kconfiglib.Kconfig(str(kconfig_path), warn=True, warn_to_stderr=True)


def _load_if_present(kconf: kconfiglib.Kconfig, path: pathlib.Path) -> None:
    if path.is_file():
        print(kconf.load_config(str(path)))


def _c_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _autoconf_header(kconf: kconfiglib.Kconfig) -> str:
    version = kconf.syms["KERNEL_VERSION"].str_value
    append = kconf.syms["KERNEL_VERSION_APPEND"].str_value
    release = version + append
    return (
        "/* Automatically generated file; DO NOT EDIT. */\n"
        f'#define EDGEOS_KERNEL_VERSION "{_c_string(version)}"\n'
        f'#define EDGEOS_KERNEL_VERSION_APPEND "{_c_string(append)}"\n'
        f'#define EDGEOS_KERNEL_RELEASE "{_c_string(release)}"\n'
    )


def _makefile_value(value: str) -> str:
    return value.replace("$", "$$").replace("#", "\\#")


def _write_makefile_config(
    kconf: kconfiglib.Kconfig,
    path: pathlib.Path,
    prefix: str,
) -> None:
    lines = [MAKEFILE_HEADER.rstrip()]
    for symbol in kconf.unique_defined_syms:
        if not symbol.name:
            continue
        config_line = symbol.config_string
        if not config_line.startswith("CONFIG_") or "=" not in config_line:
            continue
        name, value = config_line.rstrip("\n").split("=", 1)
        lines.append(f"{prefix}{name} := {_makefile_value(value)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_outputs(
    kconf: kconfiglib.Kconfig,
    config_path: pathlib.Path,
    autoconf_path: pathlib.Path,
    *,
    save_old: bool = False,
    makefile_path: pathlib.Path | None = None,
    make_prefix: str = "",
) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    autoconf_path.parent.mkdir(parents=True, exist_ok=True)
    print(
        kconf.write_config(
            str(config_path), header=CONFIG_HEADER, save_old=save_old
        )
    )
    print(
        kconf.write_autoconf(
            str(autoconf_path), header=_autoconf_header(kconf)
        )
    )
    if makefile_path is not None:
        _write_makefile_config(kconf, makefile_path, make_prefix)
        print(f"Wrote Make configuration to {makefile_path}")


def _run_menuconfig(
    kconf: kconfiglib.Kconfig,
    config_path: pathlib.Path,
    autoconf_path: pathlib.Path,
    makefile_path: pathlib.Path | None,
    make_prefix: str,
) -> None:
    try:
        import menuconfig as menuconfig_ui
    except ImportError as exc:
        if exc.name == "curses":
            raise SystemExit(
                "menuconfig requires Python's curses module backed by ncurses"
            ) from exc
        raise

    os.environ["KCONFIG_CONFIG"] = str(config_path)
    os.environ.setdefault("MENUCONFIG_STYLE", "linux")
    menuconfig_ui.menuconfig(kconf)

    # The UI saves .config itself. Reload it before generating the header so
    # choosing "No" in the quit dialog cannot leave autoconf.h describing
    # unsaved in-memory changes.
    if not config_path.is_file():
        print("Kconfig header not updated because no configuration was saved")
        return
    kconf.load_config(str(config_path))
    print(
        kconf.write_autoconf(
            str(autoconf_path), header=_autoconf_header(kconf)
        )
    )
    if makefile_path is not None:
        _write_makefile_config(kconf, makefile_path, make_prefix)
        print(f"Wrote Make configuration to {makefile_path}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Configure the EdgeOS kernel using Linux Kconfig semantics"
    )
    parser.add_argument("--kconfig", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--autoconf", required=True)
    parser.add_argument("--makefile")
    parser.add_argument("--make-prefix", default="")
    parser.add_argument("--defconfig")
    parser.add_argument("--olddefconfig", action="store_true")
    parser.add_argument("--syncconfig", action="store_true")
    parser.add_argument("--menuconfig", action="store_true")
    args = parser.parse_args()

    if args.make_prefix and re.fullmatch(
        r"[A-Za-z_][A-Za-z0-9_]*", args.make_prefix
    ) is None:
        parser.error(
            "--make-prefix must be a valid Make variable name prefix"
        )
    if args.make_prefix and not args.makefile:
        parser.error("--make-prefix requires --makefile")

    modes = (
        bool(args.defconfig),
        args.olddefconfig,
        args.syncconfig,
        args.menuconfig,
    )
    if sum(modes) != 1:
        parser.error(
            "choose exactly one of --defconfig, --olddefconfig, "
            "--syncconfig, or --menuconfig"
        )

    kconfig_path = _absolute(args.kconfig)
    config_path = _absolute(args.config)
    autoconf_path = _absolute(args.autoconf)
    makefile_path = _absolute(args.makefile) if args.makefile else None
    kconf = _new_kconfig(kconfig_path)

    if args.menuconfig:
        _run_menuconfig(
            kconf,
            config_path,
            autoconf_path,
            makefile_path,
            args.make_prefix,
        )
        return 0

    if args.defconfig:
        defconfig_path = _absolute(args.defconfig)
        if not defconfig_path.is_file():
            parser.error(f"defconfig does not exist: {defconfig_path}")
        print(kconf.load_config(str(defconfig_path)))
    else:
        _load_if_present(kconf, config_path)

    _write_outputs(
        kconf,
        config_path,
        autoconf_path,
        makefile_path=makefile_path,
        make_prefix=args.make_prefix,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
