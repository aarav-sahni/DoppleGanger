#!/usr/bin/python3
"""Install an Electron API adapter without rewriting vendor JavaScript.

Only package.json and two Doppel-owned modules change. The vendor entry point
and every vendor JavaScript bundle retain their original bytes, independently
of their names, minification, bundler, or OAuth implementation. ASAR integrity
and Electron's native integrity seal stay enabled and are refreshed locally.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

BOOTSTRAP_PATH = "doppel-bootstrap.cjs"
BOOTSTRAP_ESM_PATH = "doppel-bootstrap.mjs"
RUNTIME_PATH = "doppel-runtime.cjs"
ADAPTER_VERSION = 1
RUNTIME_SOURCE = r"""'use strict';

// Runs before the vendor entry point. Only documented Electron API boundaries
// are adapted; no vendor function names, bundles, or source text are matched.
module.exports = function installDoppelRouting({ app, shell }) {
  const scheme = process.env.DOPPEL_URL_SCHEME?.trim();
  if (!scheme || !/^[a-z][a-z0-9+.-]*$/i.test(scheme) || /^(codex|codex-dev)$/i.test(scheme)) {
    throw new Error('Doppel requires a private URL scheme');
  }
  const originalSet = app.setAsDefaultProtocolClient.bind(app);
  const originalCheck = app.isDefaultProtocolClient.bind(app);
  let claimed = false;

  function parse(value) {
    if (typeof value !== 'string') return null;
    try { return new URL(value); } catch { return null; }
  }
  function normalize(value) {
    const url = parse(value);
    if (url?.protocol.toLowerCase() !== scheme.toLowerCase() + ':') return value;
    url.protocol = 'codex:';
    return url.href;
  }
  function isCallback(value) {
    const url = parse(value);
    return url?.protocol === 'codex:' && url.hostname === 'connector' && url.pathname === '/oauth_callback';
  }
  function restorePrimary() {
    claimed = false;
    const env = process.env;
    if (!env.DOPPEL_URL_HANDLER_HELPER || !env.DOPPEL_PRIMARY_APP || !env.DOPPEL_PRIMARY_BUNDLE_ID) return;
    try {
      require('node:child_process').spawn(env.DOPPEL_URL_HANDLER_HELPER,
        ['set', 'codex', env.DOPPEL_PRIMARY_APP, env.DOPPEL_PRIMARY_BUNDLE_ID],
        { detached: true, stdio: 'ignore' }).unref();
    } catch { /* A helper failure must not swallow the vendor's callback. */ }
  }
  function claimCallback() {
    if (!originalSet('codex') && !originalCheck('codex')) {
      throw new Error('Doppel could not claim codex:// OAuth callback');
    }
    claimed = true;
  }
  function isOAuthLaunch(value) {
    const url = parse(value);
    if (!url || !['https:', 'http:'].includes(url.protocol)) return false;
    // Redirects may be nested/percent-encoded by a connector's broker. Also
    // recognize standard authorization endpoints when the broker keeps the
    // native callback server-side rather than including it in the URL.
    let decoded = value;
    for (let depth = 0; depth < 4; depth++) {
      if (/codex:\/\/connector\/oauth_callback(?:[?#&"\s]|$)/i.test(decoded)) return true;
      try {
        const next = decodeURIComponent(decoded);
        if (next === decoded) break;
        decoded = next;
      } catch { break; }
    }
    return /(?:^|\/)(?:oauth2?|authorize|authorization)(?:\/|$)/i.test(url.pathname) ||
      (url.searchParams.has('client_id') &&
        (url.searchParams.has('response_type') || url.searchParams.has('code_challenge')));
  }

  for (const method of ['setAsDefaultProtocolClient', 'isDefaultProtocolClient', 'removeAsDefaultProtocolClient']) {
    const original = app[method].bind(app);
    app[method] = function (protocol, ...args) {
      const routed = /^(codex|codex-dev)$/i.test(protocol) ? scheme : protocol;
      return original(routed, ...args);
    };
  }

  // Normalize before *all* vendor listeners, including listeners installed
  // later and early startup queues. Leave event ordering and return values intact.
  const emit = app.emit;
  app.emit = function (event, ...args) {
    let callback = false;
    if (event === 'open-url') {
      args[1] = normalize(args[1]);
      callback = isCallback(args[1]);
    } else if (event === 'second-instance' && Array.isArray(args[1])) {
      args[1] = args[1].map(normalize);
      callback = args[1].some(isCallback);
    }
    try { return emit.call(this, event, ...args); }
    finally { if (callback) restorePrimary(); }
  };
  process.argv = process.argv.map(normalize);
  if (process.argv.some(isCallback)) setImmediate(restorePrimary);

  const openExternal = shell.openExternal.bind(shell);
  shell.openExternal = async function (url, ...args) {
    const oauth = isOAuthLaunch(url);
    if (oauth) claimCallback();
    try { return await openExternal(url, ...args); }
    catch (error) { if (oauth) restorePrimary(); throw error; }
  };
  app.on('will-quit', () => { if (claimed) restorePrimary(); });
};
""".encode("utf-8")


class PatchError(RuntimeError):
    pass


@dataclass
class Archive:
    path: Path
    header: dict[str, Any]
    header_json: bytes
    data_offset: int
    size: int


@dataclass
class Member:
    path: str
    entry: dict[str, Any]
    offset: int
    size: int


def read_archive(path: Path) -> Archive:
    with path.open("rb") as archive:
        prefix = archive.read(16)
        if len(prefix) != 16:
            raise PatchError("the ASAR header is truncated")
        size_pickle_payload, header_pickle_size, header_payload, json_size = struct.unpack(
            "<IIII", prefix
        )
        if size_pickle_payload != 4:
            raise PatchError("the ASAR size pickle has an unexpected shape")
        if header_pickle_size != header_payload + 4:
            raise PatchError("the ASAR header pickle sizes disagree")
        if json_size > header_payload - 4:
            raise PatchError("the ASAR JSON size exceeds its header payload")
        header_json = archive.read(json_size)
        try:
            header = json.loads(header_json)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PatchError(f"the ASAR file table is invalid JSON: {error}") from error
        data_offset = 8 + header_pickle_size
        archive.seek(0, os.SEEK_END)
        size = archive.tell()
    if data_offset > size:
        raise PatchError("the ASAR data offset is outside the archive")
    return Archive(path, header, header_json, data_offset, size)


def members(archive: Archive) -> Iterator[Member]:
    def walk(files: dict[str, Any], parent: str = "") -> Iterator[Member]:
        for name, entry in files.items():
            member_path = f"{parent}/{name}" if parent else name
            child_files = entry.get("files")
            if isinstance(child_files, dict):
                yield from walk(child_files, member_path)
                continue
            if entry.get("unpacked") or "offset" not in entry or "size" not in entry:
                continue
            try:
                offset = int(entry["offset"])
                size = int(entry["size"])
            except (TypeError, ValueError) as error:
                raise PatchError(f"invalid offset or size for {member_path}") from error
            if offset < 0 or size < 0 or archive.data_offset + offset + size > archive.size:
                raise PatchError(f"member lies outside the archive: {member_path}")
            yield Member(member_path, entry, offset, size)

    files = archive.header.get("files")
    if not isinstance(files, dict):
        raise PatchError("the ASAR file table has no files dictionary")
    yield from walk(files)


def read_member(archive: Archive, member: Member) -> bytes:
    with archive.path.open("rb") as source:
        source.seek(archive.data_offset + member.offset)
        data = source.read(member.size)
    if len(data) != member.size:
        raise PatchError(f"member is truncated: {member.path}")
    return data


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def refresh_member_integrity(entry: dict[str, Any], data: bytes) -> None:
    integrity = entry.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256":
        raise PatchError("the protocol member lacks the expected SHA256 integrity metadata")
    block_size = integrity.get("blockSize")
    if not isinstance(block_size, int) or block_size <= 0:
        raise PatchError("the protocol member has an invalid integrity block size")
    integrity["hash"] = digest(data)
    integrity["blocks"] = [digest(data[index : index + block_size]) for index in range(0, len(data), block_size)]


def encode_header(header: dict[str, Any]) -> tuple[bytes, bytes]:
    header_json = json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    padding = b"\0" * ((-len(header_json)) % 4)
    header_payload_size = 4 + len(header_json) + len(padding)
    header_pickle_size = 4 + header_payload_size
    prefix = struct.pack(
        "<IIII", 4, header_pickle_size, header_payload_size, len(header_json)
    )
    return prefix + header_json + padding, header_json


def copy_exact(source: Any, destination: Any, count: int) -> None:
    remaining = count
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            raise PatchError("the ASAR data ended while it was being rewritten")
        destination.write(chunk)
        remaining -= len(chunk)


def verify_member_integrity(entry: dict[str, Any], data: bytes) -> None:
    integrity = entry.get("integrity")
    if not isinstance(integrity, dict) or integrity.get("algorithm") != "SHA256":
        raise PatchError("the patched member lacks SHA256 integrity metadata")
    block_size = integrity.get("blockSize")
    expected_blocks = integrity.get("blocks")
    if not isinstance(block_size, int) or block_size <= 0 or not isinstance(expected_blocks, list):
        raise PatchError("the patched member integrity metadata is invalid")
    actual_blocks = [digest(data[index : index + block_size]) for index in range(0, len(data), block_size)]
    if integrity.get("hash") != digest(data) or expected_blocks != actual_blocks:
        raise PatchError("the patched member integrity hashes do not match its contents")


def rewrite_members(archive: Archive, replacements: dict[str, bytes]) -> None:
    """Atomically replace/add members, preserving untouched member bytes."""
    originals = sorted(members(archive), key=lambda item: item.offset)
    original_paths = {member.path for member in originals}
    records = [(member.path, member.entry, member) for member in originals]
    for name in sorted(replacements.keys() - original_paths):
        if "/" in name or name in archive.header["files"]:
            raise PatchError("adapter member collides with an existing archive entry")
        entry = {}
        archive.header["files"][name] = entry
        records.append((name, entry, None))
    offset = 0
    for name, entry, member in records:
        entry["offset"] = str(offset)
        if name in replacements:
            data = replacements[name]
            entry["size"] = len(data)
            entry.setdefault("integrity", {"algorithm": "SHA256", "blockSize": 4194304})
            refresh_member_integrity(entry, data)
        offset += entry["size"]
    encoded_header, _ = encode_header(archive.header)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w+b", prefix=".doppel-asar-",
                                          dir=archive.path.parent, delete=False) as out, archive.path.open("rb") as source:
            temporary_path = Path(out.name)
            out.write(encoded_header)
            for name, _, member in records:
                if name in replacements:
                    out.write(replacements[name])
                else:
                    source.seek(archive.data_offset + member.offset)
                    copy_exact(source, out, member.size)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary_path, stat.S_IMODE(archive.path.stat().st_mode))
        os.replace(temporary_path, archive.path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def package_member(archive: Archive) -> tuple[Member, dict, dict[str, Member]]:
    files = {member.path: member for member in members(archive)}
    member = files.get("package.json")
    if member is None:
        raise PatchError("the packaged app has no package.json")
    try:
        package = json.loads(read_member(archive, member))
    except (UnicodeError, ValueError) as error:
        raise PatchError("the packaged app has invalid package.json") from error
    if not isinstance(package, dict):
        raise PatchError("the packaged app has invalid package metadata")
    return member, package, files


def entry_path(value: Any, files: dict[str, Member]) -> str:
    if not isinstance(value, str) or "\\" in value or "\0" in value:
        raise PatchError("the vendor entry point is not a safe archive path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise PatchError("the vendor entry point escapes the archive")
    name = str(path)
    if name not in files or name in (BOOTSTRAP_PATH, BOOTSTRAP_ESM_PATH, RUNTIME_PATH):
        raise PatchError("the vendor entry point is missing or collides with the adapter")
    return name


def bootstrap_source(main: str, esm: bool) -> bytes:
    if esm:
        # A genuine ESM entry with top-level await lets Electron wait for the
        # vendor module before ready, unlike fire-and-forget import from CJS.
        return ("import install from './" + RUNTIME_PATH + "';\n"
                "import * as electron from 'electron';\ninstall(electron);\n"
                "await import(" + json.dumps("./" + main) + ");\n").encode("utf-8")
    load = "module.exports = require(" + json.dumps("./" + main) + ");"
    return ("'use strict';\nrequire('./" + RUNTIME_PATH + "')(require('electron'));\n"
            + load + "\n").encode("utf-8")


def patch(path: Path) -> str:
    archive = read_archive(path)
    member, package, files = package_member(archive)
    if package.get("main") in (BOOTSTRAP_PATH, BOOTSTRAP_ESM_PATH):
        return verify(path)
    if "doppelAdapter" in package or any(name in archive.header["files"] for name in
                                        (BOOTSTRAP_PATH, BOOTSTRAP_ESM_PATH, RUNTIME_PATH)):
        raise PatchError("the archive already contains an incompatible Doppel adapter")
    main = entry_path(package.get("main", "index.js"), files)
    esm = main.endswith(".mjs") or (package.get("type") == "module" and not main.endswith(".cjs"))
    package["doppelAdapter"] = {"version": ADAPTER_VERSION, "originalMain": main,
                               "esm": esm, "originalMainSHA256": digest(read_member(archive, files[main]))}
    bootstrap = BOOTSTRAP_ESM_PATH if esm else BOOTSTRAP_PATH
    package["main"] = bootstrap
    rewrite_members(archive, {member.path: json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8"),
                              bootstrap: bootstrap_source(main, esm), RUNTIME_PATH: RUNTIME_SOURCE})
    return verify(path)


def verify(path: Path) -> str:
    archive = read_archive(path)
    member, package, files = package_member(archive)
    metadata = package.get("doppelAdapter")
    if package.get("main") not in (BOOTSTRAP_PATH, BOOTSTRAP_ESM_PATH) or not isinstance(metadata, dict):
        raise PatchError("the archive has no Doppel startup adapter")
    if metadata.get("version") != ADAPTER_VERSION or not isinstance(metadata.get("esm"), bool):
        raise PatchError("the archive has an unsupported Doppel adapter version")
    main = entry_path(metadata.get("originalMain"), files)
    if digest(read_member(archive, files[main])) != metadata.get("originalMainSHA256"):
        raise PatchError("the vendor entry point changed after adapter installation")
    bootstrap = BOOTSTRAP_ESM_PATH if metadata["esm"] else BOOTSTRAP_PATH
    if package["main"] != bootstrap:
        raise PatchError("the Doppel entry point has the wrong module format")
    expected = {bootstrap: bootstrap_source(main, metadata["esm"]), RUNTIME_PATH: RUNTIME_SOURCE}
    for name, contents in expected.items():
        if name not in files or read_member(archive, files[name]) != contents:
            raise PatchError("the Doppel adapter is missing or modified: " + name)
        verify_member_integrity(files[name].entry, contents)
    verify_member_integrity(member.entry, read_member(archive, member))
    return digest(archive.header_json)


# Electron's macOS integrity_digest.mm seals the entire plist dictionary in
# newer frameworks. Keep the seal enabled and update it before local signing.
INTEGRITY_SENTINEL = b"AGbevlPCksUGKNL8TSn7wGmJEuJsXb2A"


def dictionary_digest(integrity: dict) -> bytes:
    payload = "".join(key + integrity[key]["algorithm"] + integrity[key]["hash"]
                      for key in sorted(integrity))
    return hashlib.sha256(payload.encode("utf-8")).digest()


def refresh_integrity_slots(data: bytes, old_digest: bytes, new_digest: bytes) -> bytes:
    result = bytearray(data)
    cursor = 0
    while True:
        offset = data.find(INTEGRITY_SENTINEL, cursor)
        if offset < 0:
            break
        start = offset + len(INTEGRITY_SENTINEL)
        cursor = start + 34
        if cursor > len(data):
            raise PatchError("truncated framework integrity slot")
        used, version = data[start:start + 2]
        if used == 0:
            continue  # Older Electron builds have no dictionary seal enabled.
        if used != 1 or version != 1:
            raise PatchError("unsupported framework integrity slot version")
        if data[start + 2:cursor] != old_digest:
            raise PatchError("framework integrity digest does not match Info.plist")
        result[start + 2:cursor] = new_digest
    return bytes(result)


def sync_bundle_integrity(bundle: Path) -> list[Path]:
    contents = bundle / "Contents"
    info_path = contents / "Info.plist"
    info = plistlib.loads(info_path.read_bytes())
    integrity = info["ElectronAsarIntegrity"]
    old_digest = dictionary_digest(integrity)
    integrity["Resources/app.asar"]["hash"] = verify(contents / "Resources/app.asar")
    new_digest = dictionary_digest(integrity)
    changes = []
    for framework in sorted((contents / "Frameworks").glob("*.framework")):
        binary = (framework / framework.stem).resolve()
        if not binary.is_relative_to(contents.resolve()):
            raise PatchError("framework executable resolves outside staging bundle")
        if not binary.is_file():
            continue
        data = binary.read_bytes()
        updated = refresh_integrity_slots(data, old_digest, new_digest)
        if updated != data:
            changes.append((framework, binary, updated))
    # Validate every slot before writing anything. The engine discards staging
    # on any failure and re-signs each changed framework before sealing the app.
    for framework, binary, updated in changes:
        binary.write_bytes(updated)
    info_path.write_bytes(plistlib.dumps(info))
    return [framework for framework, _, _ in changes]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("patch", "verify", "sync-integrity"))
    parser.add_argument("archive", type=Path)
    arguments = parser.parse_args()
    if arguments.mode == "sync-integrity":
        try:
            for framework in sync_bundle_integrity(arguments.archive):
                print(framework)
        except (OSError, ValueError, KeyError, TypeError, PatchError) as error:
            print(f"patch-deep-link: {error}", file=sys.stderr)
            return 1
        return 0
    if not arguments.archive.is_file():
        parser.error(f"archive does not exist: {arguments.archive}")
    try:
        header_hash = patch(arguments.archive) if arguments.mode == "patch" else verify(arguments.archive)
    except (OSError, PatchError) as error:
        print(f"patch-deep-link: {error}", file=sys.stderr)
        return 1
    print(header_hash)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
