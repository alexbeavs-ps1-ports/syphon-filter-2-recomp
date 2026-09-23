"""Final ZIP gate, shared by local collection and native CI jobs.

No retail inputs. Native smoke runs the two setup generators with --help from
a fresh directory containing spaces. It does not claim setup or gameplay.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform as host_platform
import re
import struct
import subprocess
import sys
import tempfile
import zipfile

from audit_release_payload import audit_archive, tomllib, PLATFORMS
from audit_macos_setup import audit as audit_mac, version_number
from audit_setup_package_platform_copy import audit as audit_copy


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True, encoding='utf-8', errors='replace').strip()


def committed_recipe_hashes(root):
    """Bind exact committed bytes; platform checkout conversion is not a new recipe."""
    root = Path(root)
    result = {}
    for name in ('game.toml', 'catalog_identity.json', 'codegen_setup.c', 'CMakeLists.txt'):
        committed = subprocess.check_output(['git', '-C', str(root), 'show', 'HEAD:' + name])
        if (root / name).read_bytes() != committed:
            raise ValueError('recipe checkout differs from committed bytes: ' + name +
                             '; use core.autocrlf=false before checkout and retain committed content')
        result[name] = hashlib.sha256(committed).hexdigest()
    return result


def source_contract(root, version):
    """Bind the committed recipe and reject a mismatched deferred launch name."""
    root = Path(root)
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?', version):
        raise ValueError('version must be an explicit X.Y.Z value, optionally with a prerelease suffix')
    cmake = (root / 'CMakeLists.txt').read_text(encoding='utf-8-sig')
    codegen = (root / 'codegen_setup.c').read_text(encoding='utf-8-sig')
    wrapper = (root / 'scripts/package_setup_release.sh').read_text(encoding='utf-8-sig')
    def capture(text, pattern):
        match = re.search(pattern, text, re.M)
        if not match:
            raise ValueError('missing literal executable name: ' + pattern)
        return next(g for g in match.groups() if g is not None)
    title = capture(cmake, r'^\s*WINDOW_TITLE\s+"([^"]+)"')
    explicit = re.search(r'^\s*EXE_NAME\s+"([^"]+)"', cmake, re.M)
    exe = explicit[1] if explicit else re.sub('[^A-Za-z0-9_]', '_', title)
    if not explicit and exe[0].isdigit():
        exe = '_' + exe
    names = [exe, capture(codegen, r'\.exe_basename\s*=\s*"([^"]+)"'),
             capture(wrapper, r'--exe-name\s+(?:"([^"]+)"|\'([^\']+)\'|([^\s\\]+))')]
    if len(set(names)) != 1:
        raise ValueError('executable names differ: ' + repr(names))
    if b'\r' in (root / 'scripts/package_setup_release.sh').read_bytes() or '--runtime-dir' not in wrapper or 'project-manifest.toml' not in wrapper:
        raise ValueError('wrapper requires LF, runtime mods, and project-manifest.toml')
    manifest = tomllib.loads((root / 'project-manifest.toml').read_text(encoding='utf-8-sig'))
    git = lambda *args: command(['git', '-C', str(root), *args])
    framework = git('rev-parse', 'HEAD:psxrecomp')
    ui = git('rev-parse', 'HEAD:recomp-ui')
    if manifest['framework']['commit'] != framework or manifest['framework']['recomp_ui_commit'] != ui:
        raise ValueError('manifest dependencies differ from committed gitlinks')
    if git('-C', 'psxrecomp', 'rev-parse', 'HEAD') != framework:
        raise ValueError('framework checkout differs from committed gitlink')
    if git('-C', 'recomp-ui', 'rev-parse', 'HEAD') != ui:
        raise ValueError('UI checkout differs from committed gitlink')
    tree = git('-C', 'psxrecomp', 'rev-parse', 'HEAD^{tree}')
    if manifest['framework']['tree'] != tree:
        raise ValueError('framework tree mismatch')
    if str(manifest['release']['version']).lstrip('v') != version:
        raise ValueError('freeze the manifest version before the build')
    if (root / 'VERSION').read_text(encoding='utf-8-sig').strip() != version:
        raise ValueError('VERSION differs from frozen manifest')
    pins = {'version': version, 'source_commit': git('rev-parse', 'HEAD'),
            'framework_commit': framework, 'framework_tree': tree, 'recomp_ui_commit': ui,
            'recomp_net_commit': git('-C', 'psxrecomp', 'rev-parse', 'HEAD:lib/recomp-net'),
            'rbengine_commit': git('-C', 'psxrecomp', 'rev-parse', 'HEAD:lib/retcomm-rbengine'),
            'exe_name': exe, 'openbios_required': False}
    # An explicit source policy binds OpenBIOS identity. Publication still needs R4.
    policy_path = root / '.release/policy.json'
    if policy_path.exists():
        policy = json.loads(policy_path.read_text(encoding='utf-8'))
        pins['openbios_required'] = policy.get('openbios_required', False)
    pins['recipe_sha256'] = committed_recipe_hashes(root)
    return pins


def binary_arch(raw):
    if raw.startswith(b'MZ'):
        if len(raw) < 64:
            raise ValueError('truncated PE header')
        offset = struct.unpack_from('<I', raw, 60)[0]
        if offset + 6 > len(raw) or raw[offset:offset + 4] != b'PE\0\0':
            raise ValueError('invalid PE header')
        return 'windows-x64' if struct.unpack_from('<H', raw, offset + 4)[0] == 0x8664 else 'wrong-pe-cpu'
    if raw.startswith(b'\x7fELF'):
        if len(raw) < 64 or raw[4:6] != b'\x02\x01':
            raise ValueError('expected ELF64 little endian')
        return 'linux-x64' if struct.unpack_from('<H', raw, 18)[0] == 62 else 'wrong-elf-cpu'
    if raw.startswith(b'\xcf\xfa\xed\xfe'):
        from audit_macos_setup import read_macho, CPUS
        parsed = read_macho(io.BytesIO(raw))
        return next((p for p, c in CPUS.items() if c == parsed['cpu']), 'wrong-mach-cpu')
    return None


def native_platform():
    system = host_platform.system()
    machine = host_platform.machine().lower()
    if machine not in ('amd64', 'x86_64', 'arm64', 'aarch64'):
        return 'unsupported'
    cpu = 'arm64' if machine in ('arm64', 'aarch64') else 'x64'
    return {'Windows': 'windows', 'Linux': 'linux', 'Darwin': 'macos'}.get(system, 'unsupported') + '-' + cpu


def linux_dependencies(binary):
    """Check undefined versioned imports, not coincidental strings in data."""
    output = command(['objdump', '-T', str(binary)])
    result = {}
    for family, maximum in [('GLIBC', (2, 31)), ('GLIBCXX', (3, 4, 28)), ('CXXABI', (1, 3, 12))]:
        versions = [tuple(map(int, v.split('.'))) for line in output.splitlines() if '*UND*' in line
                    for v in re.findall(r'\b' + family + r'_(\d+(?:\.\d+)+)\b', line)]
        if versions:
            highest = max(versions)
            result[family] = '.'.join(map(str, highest))
            if highest > maximum:
                raise ValueError(f'{binary.name}: requires {family}_{result[family]}')
    linked = command(['ldd', str(binary)])
    if 'not found' in linked:
        raise ValueError(f'{binary.name}: missing native dependency: ' + '; '.join(line.strip() for line in linked.splitlines() if 'not found' in line))
    result['ldd'] = linked
    return result


def check_package(path, expected, platform, native=False, macos='11.0'):
    path = Path(path).resolve()
    result = audit_archive(path, expected.get('repo', 'local'), expected)
    result['schema'] = 'psx.package-gate.v1'
    result['checks'] = {'payload': result['status'], 'native_generators': 'not_run',
                        'native_setup': 'not_run', 'gameplay': 'not_run'}
    result['source_commit'] = expected['source_commit']
    result['runner'] = {'platform': native_platform(), 'system': host_platform.platform(),
                        'run_id': os.environ.get('GITHUB_RUN_ID'),
                        'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
    problems = result['problems']
    try:
        result['platform_copy'] = audit_copy(path)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        problems.append('platform setup copy: ' + str(exc))
    if result['platform'] != platform:
        problems.append('requested platform differs from archive name')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        suffix = '.exe' if platform == 'windows-x64' else ''
        exe = expected.get('exe_name')
        if not exe:
            roots = [n for n in names if '/' not in n and not n.endswith('/')
                     and binary_arch(archive.read(n)) == platform]
            if len(roots) != 1:
                problems.append('expected one native root setup host')
            else:
                exe = roots[0][:-len(suffix)] if suffix else roots[0]
        required = [str(exe) + suffix] + ['psxrecomp/recompiler/build/' + n + suffix
                                          for n in ('psxrecomp-game', 'psxrecomp-bios')]
        result['native_binaries'] = required
        for name in required:
            if name not in names:
                problems.append('missing executable: ' + name)
                continue
            raw = archive.read(name)
            if binary_arch(raw) != platform:
                problems.append('wrong executable architecture: ' + name)
            if platform != 'windows-x64' and not (archive.getinfo(name).external_attr >> 16) & 0o111:
                problems.append('missing executable permission: ' + name)
        for name, wanted in expected.get('recipe_sha256', {}).items():
            if name not in names or hashlib.sha256(archive.read(name)).hexdigest() != wanted:
                problems.append('package differs from frozen recipe: ' + name)
        if platform.startswith('macos'):
            mac = audit_mac(result, version_number(macos))
            result['macos'] = mac
            problems.extend(mac['errors'])
        if native and not problems:
            if native_platform() != platform:
                problems.append('native smoke requested on wrong operating system or architecture')
            else:
                # Extract only audited executable paths. Never invoke arbitrary archive helpers.
                with tempfile.TemporaryDirectory(prefix='psx package smoke ') as temporary:
                    stage = Path(temporary)
                    for name in required + [n for n in names if '/' not in n and n.lower().endswith('.dll')]:
                        target = stage / name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(archive.read(name))
                        target.chmod(0o755)
                    try:
                        result['dependency_checks'] = {}
                        for name in required:
                            if platform == 'linux-x64':
                                result['dependency_checks'][name] = linux_dependencies(stage / name)
                            elif platform.startswith('macos'):
                                command(['codesign', '--verify', '--strict', str(stage / name)])
                        smoke = []
                        for name in required[1:]:
                            process = subprocess.run([str(stage / name), '--help'], cwd=stage,
                                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
                            output = process.stdout + process.stderr
                            smoke.append({'file': name, 'exit_code': process.returncode, 'output': output[:6000]})
                            if process.returncode or not re.search(r'usage|options', output, re.I):
                                raise ValueError('native generator --help failed: ' + name)
                        result['smoke'] = smoke
                        result['checks']['native_generators'] = 'passed'
                    except (OSError, ValueError, subprocess.SubprocessError) as exc:
                        problems.append(str(exc))
                        result['checks']['native_generators'] = 'failed'
    result['status'] = 'fail' if problems else 'pass'
    result['checks']['archive'] = 'passed' if not problems else 'failed'
    # Only successful checks enter the reusable cache. Setup and gameplay stay separate.
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--expected', type=Path)
    parser.add_argument('--version')
    parser.add_argument('--zip', type=Path)
    parser.add_argument('--platform', choices=PLATFORMS)
    parser.add_argument('--native', action='store_true')
    parser.add_argument('--preflight', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error('output already exists')
    try:
        expected = (json.loads(args.expected.read_text(encoding='utf-8-sig')) if args.expected
                    else source_contract(args.source, args.version))
        result = {'schema': 'psx.source-gate.v1', 'status': 'pass', 'expected': expected}
        if not args.preflight:
            result = check_package(args.zip, expected, args.platform, args.native)
    except (OSError, ValueError, KeyError, struct.error, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        result = {'schema': 'psx.package-gate.v1', 'status': 'fail', 'problems': [str(exc)]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'status': result['status'], 'output': str(args.output), 'problems': result.get('problems', [])}))
    return 0 if result['status'] == 'pass' else 1


if __name__ == '__main__':
    raise SystemExit(main())
