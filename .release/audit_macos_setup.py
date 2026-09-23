"""Inspect thin Mach-O binaries in exact PSX setup ZIPs without executing them.

The manifest input is the existing package-audit JSON with results containing
platform, local_path, bytes and sha256. This checks binary metadata, not native
launch, signatures, runtime-loaded plugins, or transitive system dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import zipfile

CPUS = {"macos-arm64": 0x100000c, "macos-x64": 0x1000007}
FAT_MAGIC = {b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca', b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}


def version(value):
    return f"{value >> 16}.{(value >> 8) & 255}.{value & 255}"


def version_number(text):
    fields = text.split('.')
    if not 1 <= len(fields) <= 3 or not all(p.isdecimal() for p in fields):
        raise ValueError("macOS version must be MAJOR[.MINOR[.PATCH]]")
    parts = [int(p) for p in fields] + [0] * (3 - len(fields))
    if parts[0] > 65535 or any(p > 255 for p in parts[1:]):
        raise ValueError("macOS version component exceeds Mach-O encoding")
    return (parts[0] << 16) | (parts[1] << 8) | parts[2]


def read_macho(stream):
    header = stream.read(32)
    if header[:4] in FAT_MAGIC:
        raise ValueError("universal Mach-O needs a separate per-slice audit")
    if header[:4] != b'\xcf\xfa\xed\xfe':
        return None
    if len(header) != 32:
        raise ValueError("truncated Mach-O header")
    cpu, _, filetype, count, size, _, _ = struct.unpack('<7I', header[4:])
    if size > 1024 * 1024 or count > size // 8:
        raise ValueError("invalid or excessive load-command size")
    commands = stream.read(size)
    if len(commands) != size:
        raise ValueError("truncated load commands")
    result = dict(cpu=cpu, filetype=filetype, minimum_os=[], dependencies=[], rpaths=[])
    offset = 0
    for _ in range(count):
        if offset + 8 > size:
            raise ValueError("load command exceeds header size")
        command, length = struct.unpack_from('<II', commands, offset)
        if length < 8 or length % 8 or offset + length > size:
            raise ValueError("invalid load-command boundary")
        chunk = commands[offset:offset + length]
        if command in (0xc, 0x80000018, 0x8000001f, 0x80000023, 0x8000001c):
            minimum = 12 if command == 0x8000001c else 24
            if length < minimum:
                raise ValueError("truncated dynamic library command")
            start = struct.unpack_from('<I', chunk, 8)[0]
            if not minimum <= start < length or b'\0' not in chunk[start:]:
                raise ValueError("invalid dynamic library name")
            name = chunk[start:].split(b'\0', 1)[0].decode('utf-8')
            result['rpaths' if command == 0x8000001c else 'dependencies'].append(name)
        elif command == 0x32:
            if length < 24:
                raise ValueError("truncated build-version command")
            platform, minimum, _ = struct.unpack_from('<III', chunk, 8)
            if platform != 1:
                raise ValueError("binary declares a non-macOS platform")
            result['minimum_os'].append(version(minimum))
        elif command == 0x24:
            if length < 16:
                raise ValueError("truncated minimum-version command")
            result['minimum_os'].append(version(struct.unpack_from('<I', chunk, 8)[0]))
        offset += length
    if offset != size:
        raise ValueError("load commands do not cover their declared size")
    return result


def audit(row, max_version):
    path = Path(row['local_path'])
    result = {"file": row['file'], "platform": row['platform'], "errors": [], "binaries": []}
    try:
        hasher = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                hasher.update(block)
        digest = hasher.hexdigest()
        result['sha256'] = digest
        if digest.lower() != row['sha256'].lower() or path.stat().st_size != row['bytes']:
            raise ValueError("archive bytes differ from input receipt")
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("duplicate archive entry")
            for info in archive.infolist():
                if info.is_dir():
                    continue
                with archive.open(info) as stream:
                    binary = read_macho(stream)
                if binary is None:
                    continue
                binary['name'] = info.filename
                result['binaries'].append(binary)
                if binary['cpu'] != CPUS[row['platform']]:
                    result['errors'].append(f"{info.filename}: architecture mismatch")
                if not binary['minimum_os']:
                    result['errors'].append(f"{info.filename}: missing minimum OS")
                for minimum in binary['minimum_os']:
                    if version_number(minimum) > max_version:
                        result['errors'].append(f"{info.filename}: requires macOS {minimum}")
                for dep in binary['dependencies']:
                    if dep.startswith('/') and not dep.startswith(('/usr/lib/', '/System/Library/')):
                        result['errors'].append(f"{info.filename}: external non-system dependency {dep}")
            binaries = {b['name'] for b in result['binaries']}
            required = {'psxrecomp/recompiler/build/psxrecomp-game', 'psxrecomp/recompiler/build/psxrecomp-bios'}
            if not required <= binaries or not any('/' not in n for n in binaries):
                result['errors'].append("missing native setup host or code generator")
    except (OSError, ValueError, zipfile.BadZipFile, struct.error) as exc:
        result['errors'].append(str(exc))
    result['status'] = 'fail' if result['errors'] else 'pass'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-audit', required=True, type=Path)
    parser.add_argument('--max-macos', required=True, type=version_number)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error('output exists; choose a new receipt path')
    document = json.loads(args.package_audit.read_text(encoding='utf-8-sig'))
    rows = [r for r in document['results'] if r['platform'] in CPUS]
    paths = [str(Path(r['local_path']).resolve()) for r in rows]
    if not rows or len(set(paths)) != len(rows):
        parser.error('selected macOS inputs must be non-empty and unique')
    results = [audit(row, args.max_macos) for row in rows]
    result = dict(schema=1, scope='exact archive identity and thin Mach-O metadata; no runtime test',
                  max_macos=version(args.max_macos), package_count=len(rows), results=results,
                  status='pass' if all(r['status']=='pass' for r in results) else 'fail')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(package_count=len(rows), failed=sum(r['status']=='fail' for r in results), status=result['status'])))
    return 0 if result['status']=='pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
