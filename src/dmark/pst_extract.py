from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


class PstExtractError(RuntimeError):
    pass


def get_pst_backend_status() -> dict[str, bool]:
    return {
        "pypff": has_pypff(),
        "readpst": has_readpst(),
        "pstparse_dotnet": has_pstparse_dotnet(),
    }


def has_pypff() -> bool:
    try:
        import pypff  # type: ignore  # noqa: F401

        return True
    except ImportError:
        return False


def has_readpst() -> bool:
    return shutil.which("readpst") is not None


def has_pstparse_dotnet() -> bool:
    if shutil.which("dotnet") is None:
        return False
    project = _pstparse_project_path()
    return project.exists()


def install_pstparse_dotnet_noninteractive() -> tuple[bool, str]:
    if shutil.which("dotnet") is None:
        return False, "dotnet SDK/runtime is not available in PATH."

    project = _pstparse_project_path()
    if not project.exists():
        return False, f"PSTParse helper project not found at {project}"

    dll_path = _pstparse_helper_dll_path()
    if dll_path.exists():
        return True, f"PSTParse .NET helper is ready at {dll_path}"

    build_root = _pstparse_build_root()
    obj_root = build_root / "obj"
    bin_root = build_root / "bin"
    obj_root.mkdir(parents=True, exist_ok=True)
    bin_root.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        [
            "dotnet",
            "build",
            str(project),
            "-c",
            "Release",
            "--nologo",
            f"-p:BaseIntermediateOutputPath={obj_root}{os.sep}",
            f"-p:OutputPath={bin_root}{os.sep}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        combined = (stderr + "\n" + stdout).strip()
        return False, f"PSTParse helper build failed: {combined or 'unknown error'}"

    if not dll_path.exists():
        return False, "PSTParse helper build completed but output DLL was not found."

    return True, f"PSTParse .NET helper is ready at {dll_path}"


def extract_reports_from_pst(
    pst_path: Path,
    out_dir: Path,
    engine: str = "auto",
) -> tuple[list[Path], str]:
    pst_path = pst_path.resolve()
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not pst_path.exists():
        raise PstExtractError(f"PST file not found: {pst_path}")

    if engine not in {"auto", "pypff", "readpst", "pstparse-dotnet"}:
        raise PstExtractError(f"Unsupported engine: {engine}")

    errors: list[str] = []

    if engine in {"auto", "pypff"}:
        try:
            extracted = _extract_with_pypff(pst_path=pst_path, out_dir=out_dir)
            return extracted, "pypff"
        except Exception as exc:
            errors.append(f"pypff failed: {exc}")
            if engine == "pypff":
                raise PstExtractError("; ".join(errors)) from exc

    if engine in {"auto", "readpst"}:
        try:
            extracted = _extract_with_readpst(pst_path=pst_path, out_dir=out_dir)
            return extracted, "readpst"
        except Exception as exc:
            errors.append(f"readpst failed: {exc}")
            if engine == "readpst":
                raise PstExtractError("; ".join(errors)) from exc

    if engine in {"auto", "pstparse-dotnet"}:
        try:
            extracted = _extract_with_pstparse_dotnet(pst_path=pst_path, out_dir=out_dir)
            return extracted, "pstparse-dotnet"
        except Exception as exc:
            errors.append(f"pstparse-dotnet failed: {exc}")
            if engine == "pstparse-dotnet":
                raise PstExtractError("; ".join(errors)) from exc

    raise PstExtractError(
        "Unable to extract DMARC attachments from PST. "
        + " | ".join(errors)
        + " | Install pypff, readpst, or PSTParse .NET helper."
    )


def _extract_with_pypff(pst_path: Path, out_dir: Path) -> list[Path]:
    if not has_pypff():
        raise PstExtractError(
            "pypff is not installed. Install python-libpff bindings or use readpst."
        )

    import pypff  # type: ignore

    seen_hashes: set[str] = set()
    written_files: list[Path] = []
    sequence = 0

    pst_file = pypff.file()
    pst_file.open(str(pst_path))
    root_folder = pst_file.get_root_folder()

    def walk_folder(folder) -> None:
        nonlocal sequence
        for message_index in range(folder.number_of_sub_messages):
            message = folder.get_sub_message(message_index)
            for attachment_index in range(message.number_of_attachments):
                attachment = message.get_attachment(attachment_index)
                name = (
                    getattr(attachment, "get_long_filename", lambda: "")() or ""
                ) or (getattr(attachment, "get_filename", lambda: "")() or "")
                if not _looks_like_dmarc_attachment(name):
                    continue
                size = attachment.get_size()
                data = attachment.read_buffer(size)
                file_hash = hashlib.sha256(data).hexdigest()
                if file_hash in seen_hashes:
                    continue
                seen_hashes.add(file_hash)
                sequence += 1
                ext = _normalized_extension(name)
                output_path = out_dir / f"report_{sequence:06d}{ext}"
                output_path.write_bytes(data)
                written_files.append(output_path)

        for folder_index in range(folder.number_of_sub_folders):
            sub_folder = folder.get_sub_folder(folder_index)
            walk_folder(sub_folder)

    walk_folder(root_folder)
    pst_file.close()
    return written_files


def _extract_with_readpst(pst_path: Path, out_dir: Path) -> list[Path]:
    if not has_readpst():
        raise PstExtractError("readpst executable is not available in PATH.")

    temp_dir = out_dir / "_readpst_tmp"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "readpst",
        "-r",
        "-D",
        "-b",
        "-o",
        str(temp_dir),
        str(pst_path),
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise PstExtractError(
            f"readpst failed with exit code {result.returncode}: {result.stderr.strip()}"
        )

    seen_hashes: set[str] = set()
    written_files: list[Path] = []
    sequence = 0
    for candidate in temp_dir.rglob("*"):
        if not candidate.is_file():
            continue
        if not _looks_like_dmarc_attachment(candidate.name):
            continue
        data = candidate.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        sequence += 1
        ext = _normalized_extension(candidate.name)
        output_path = out_dir / f"report_{sequence:06d}{ext}"
        output_path.write_bytes(data)
        written_files.append(output_path)

    shutil.rmtree(temp_dir, ignore_errors=True)
    return written_files


def _extract_with_pstparse_dotnet(pst_path: Path, out_dir: Path) -> list[Path]:
    dll_path = _build_pstparse_dotnet_helper()
    cmd = ["dotnet", str(dll_path), str(pst_path), str(out_dir)]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        stdout = (result.stdout or "").strip()
        combined = (stderr + "\n" + stdout).strip()
        raise PstExtractError(
            f"pstparse-dotnet extractor failed with exit code {result.returncode}: {combined}"
        )

    payload = {}
    stdout = (result.stdout or "").strip()
    if stdout:
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
                break
            except json.JSONDecodeError:
                continue

    if payload.get("errors"):
        first = payload["errors"][0]
        raise PstExtractError(f"pstparse-dotnet reported extraction errors: {first}")

    files: list[Path] = []
    for candidate in out_dir.rglob("*"):
        if candidate.is_file() and _looks_like_dmarc_attachment(candidate.name):
            files.append(candidate)
    return sorted(files)


def _pstparse_project_path() -> Path:
    return Path(__file__).resolve().parents[2] / "tools" / "pstparse_extractor" / "pstparse_extractor.csproj"


def _pstparse_helper_dll_path() -> Path:
    return _pstparse_build_root() / "bin" / "pstparse_extractor.dll"


def _build_pstparse_dotnet_helper() -> Path:
    project = _pstparse_project_path()
    if not project.exists():
        raise PstExtractError(f"PSTParse helper project not found: {project}")
    if shutil.which("dotnet") is None:
        raise PstExtractError("dotnet is not available in PATH.")

    dll_path = _pstparse_helper_dll_path()
    if dll_path.exists():
        return dll_path

    ok, message = install_pstparse_dotnet_noninteractive()
    if not ok:
        raise PstExtractError(message)
    return _pstparse_helper_dll_path()


def _pstparse_build_root() -> Path:
    return Path(__file__).resolve().parents[2] / ".dmark_cache" / "pstparse_dotnet"


def _looks_like_dmarc_attachment(filename: str) -> bool:
    name = (filename or "").lower()
    return name.endswith(".xml") or name.endswith(".xml.gz") or name.endswith(".gz")


def _normalized_extension(filename: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".xml.gz"):
        return ".xml.gz"
    if name.endswith(".xml"):
        return ".xml"
    if name.endswith(".gz"):
        return ".gz"
    return ".bin"
