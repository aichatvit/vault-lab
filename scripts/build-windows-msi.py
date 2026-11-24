#!/usr/bin/env python3
"""Build the per-user x64 MSI with wixl, checking the runtime payload first."""

import argparse
import re
import shutil
import subprocess
import tempfile
import tomllib
import uuid
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
PACKAGING = PROJECT / "packaging" / "windows"
# Imports supplied by the supported Windows desktop OS. Any other DLL must
# be explicitly inspected and packaged when changing the compiler or plugin.
SYSTEM_DLLS = {
    "bcrypt.dll", "bcryptprimitives.dll", "cldapi.dll", "kernel32.dll",
    "msvcrt.dll", "ntdll.dll", "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "user32.dll", "userenv.dll", "ws2_32.dll",
}


def check_binary(path):
    output = subprocess.check_output(
        ["llvm-readobj", "--file-headers", "--coff-imports", str(path)], text=True
    )
    if "IMAGE_FILE_MACHINE_AMD64" not in output:
        raise SystemExit(f"Expected Windows x64 PE: {path}")
    imports = {name.lower() for name in re.findall(r"^  Name: (.+)$", output, re.M)}
    missing = sorted(dll for dll in imports if dll not in SYSTEM_DLLS
                     and not dll.startswith(("api-ms-win-", "ext-ms-win-")))
    if missing:
        raise SystemExit(f"{path.name} requires additional DLLs: {', '.join(missing)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", required=True, type=Path, help="vendor x64 aldcrypto.dll")
    parser.add_argument("--exe", type=Path, default=PROJECT / "target/x86_64-pc-windows-gnu/release/vault-lab.exe")
    args = parser.parse_args()
    with (PROJECT / "Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["package"]["version"]
    # A fixed product code per version keeps rebuilding the same release from
    # creating a second entry in Installed Apps. UpgradeCode lives in the WXS.
    product = uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/aichatvit/vault-lab/msi/x64/{version}")
    dest = PROJECT / "target" / "installer"
    dest.mkdir(parents=True, exist_ok=True)
    name = f"VaultLab-{version}-x64.msi"
    with tempfile.TemporaryDirectory(dir=dest) as tmp:
        stage = Path(tmp)
        for source, installed_name in [(args.exe, "vault-lab.exe"), (args.plugin, "aldcrypto.dll")]:
            shutil.copyfile(source, stage / installed_name)
            check_binary(stage / installed_name)
        shutil.copyfile(PACKAGING / "VaultLab.wxs", stage / "VaultLab.wxs")
        guide = (PACKAGING / "S-Box.txt").read_text(encoding="utf-8")
        (stage / "S-Box.txt").write_bytes(guide.replace("\n", "\r\n").encode("utf-8-sig"))
        subprocess.run(["wixl", "-a", "x64", "-D", f"Version={version}", "-D",
                        f"ProductCode={str(product).upper()}", "-o", name, "VaultLab.wxs"],
                       cwd=stage, check=True)
        # wixl writes x64;1033 even for Russian products. Match the summary
        # template to ProductLanguage for Windows Installer language validation.
        subprocess.run(["msibuild", name, "-s", "Vault Lab S-Box", "Vault Lab", "x64;1049"],
                       cwd=stage, check=True)
        (stage / name).replace(dest / name)
    print(dest / name)


if __name__ == "__main__":
    main()
