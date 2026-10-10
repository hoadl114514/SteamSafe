from pathlib import Path
import zipfile

root = Path(__file__).parents[1]
exclude = {".venv", ".release-keys", ".build-cache", ".reference", "research", "build", "dist", "test-output", "__pycache__", ".git"}
output = root / "dist/SteamSafe-v0.1.2.6-Beta-source.zip"
with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
    for file in sorted(root.rglob("*")):
        relative = file.relative_to(root)
        if not file.is_file() or any(part in exclude for part in relative.parts) or file.suffix in (".spec", ".pyc"):
            continue
        archive.write(file, "SteamSafe/" + relative.as_posix())
with zipfile.ZipFile(output) as archive:
    names = archive.namelist()
    assert not any(".release-keys" in name or ".build-cache" in name or ".venv" in name for name in names)
print(f"Source archive: {len(names)} files, {output.stat().st_size} bytes; private keys and build caches excluded")
