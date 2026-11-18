#!/usr/bin/env python3
"""Build a rootless or rootful Debian package and a flat, signed Sileo/APT repository."""
import argparse
import bz2
import datetime
import gzip
import hashlib
import html
import json
import lzma
from pathlib import Path
import plistlib
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'io.github.10.slipstream'
# Install prefix → Debian architecture. Rootful jailbreaks (every iOS 14 jailbreak) use /.
ARCHES = {'/var/jb': 'iphoneos-arm64', '': 'iphoneos-arm'}
REPO = 'https://10.github.io/slipstream-ios/'
SOURCE = 'https://github.com/10/slipstream-ios'

def run(*args):
    return subprocess.check_output(args, text=True).strip()

def version(value):
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        raise ValueError('Version must be MAJOR.MINOR.PATCH, such as 0.3.0')
    return value

def notices():
    metadata = json.loads(run('cargo', 'metadata', '--locked', '--format-version', '1', '--filter-platform', 'aarch64-apple-ios'))
    reachable = {node['id'] for node in metadata['resolve']['nodes']}
    allowed = {'MIT', 'Apache-2.0', 'Unicode-3.0', 'ISC', 'Zlib', 'WTFPL', 'Unlicense', 'BSD-2-Clause', 'LLVM-exception'}
    sections = ['Slipstream third-party notices\n\nOnly dependencies in the active iOS build are included.\n']
    for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
        if package['id'] not in reachable or package['id'] == metadata['resolve']['root']:
            continue
        license = package.get('license') or ''
        tokens = set(re.findall(r'[A-Za-z0-9][A-Za-z0-9.\-]*', license)) - {'OR', 'AND', 'WITH'}
        if not tokens or tokens - allowed:
            raise ValueError(f"Review distribution license for {package['name']}: {license}")
        base = Path(package['manifest_path']).parent
        files = {p for pattern in ('LICENSE*', 'LICENCE*', 'COPYING*', 'NOTICE*', 'COPYRIGHT*') for p in base.glob(pattern) if p.is_file()}
        if package.get('license_file'):
            files.add(base / package['license_file'])
        if not files:
            supplement = ROOT / f"packaging/licenses/{package['name']}-{package['version']}.txt"
            if supplement.is_file(): files.add(supplement)
        if not files:
            raise ValueError(f"Missing license text for {package['name']}")
        sections.append(f"\n{'=' * 72}\n{package['name']} {package['version']} — {license}\n")
        for path in sorted(files):
            sections.append(f'\n--- {path.name} ---\n{path.read_text()}\n')
    output = ROOT / 'build/THIRD_PARTY-LICENSES.txt'
    output.write_text(''.join(sections))
    return output

def package(ver):
    ver = version(ver)
    source = ROOT / 'build/install'
    if plistlib.loads((source / 'Slipstream.app/Info.plist').read_bytes())['CFBundleShortVersionString'] != ver:
        raise ValueError('Rebuild with SLIPSTREAM_VERSION matching the package version')
    # build.sh writes the scheme's prefix into slipstreamctl, so its shebang identifies the build.
    prefix = '/var/jb' if (source / 'slipstreamctl').read_text().startswith('#!/var/jb/') else ''
    arch = ARCHES[prefix]
    stage = ROOT / 'build/deb-stage'
    if stage.exists():
        shutil.rmtree(stage)
    base = stage / prefix.lstrip('/')
    binaries = base / 'usr/local/bin'
    binaries.mkdir(parents=True)
    for name in ('slipstream', 'slipstreamctl'):
        shutil.copy2(source / name, binaries / name)
    shutil.copytree(source / 'Slipstream.app', base / 'Applications/Slipstream.app')
    doc = base / f'usr/share/doc/{PACKAGE}'
    doc.mkdir(parents=True)
    (doc / 'copyright').write_text((ROOT / 'LICENSE').read_text() + '\n' + notices().read_text())
    keys = base / 'etc/apt/trusted.gpg.d'
    keys.mkdir(parents=True)
    shutil.copy2(ROOT / 'packaging/repository-key.gpg', keys / 'slipstream.gpg')
    control = stage / 'DEBIAN'
    control.mkdir()
    (control / 'control').write_text(f'''Package: {PACKAGE}
Name: Slipstream
Version: {ver}
Architecture: {arch}
Maintainer: Anson <48256568+10@users.noreply.github.com>
Author: Anson
Section: Utilities
Priority: optional
Depends: firmware (>= 14.0), uikittools (>= 2.1.2)
Homepage: {SOURCE}
Depiction: {REPO}
Icon: {REPO}CydiaIcon.png
Description: Per-app HTTP CONNECT / SOCKS5 proxy tunnel
 Routes apps' Internet traffic through your proxy using an iOS app proxy,
 which creates no tunnel interface.
 Includes a Home Screen app, proxy lists, app selection and latency checks.
 Requires an active {'rootless' if prefix else 'rootful'} jailbreak.
 HTTP proxies carry TCP only; SOCKS5 proxies can also relay UDP.
''')
    template = (ROOT / 'packaging/maintainer.sh').read_text()
    for name in ('preinst', 'postinst', 'prerm', 'postrm'):
        (control / name).write_text(template.replace('@SCRIPT@', name).replace('/var/jb', prefix))
    for path in stage.rglob('*'):
        path.chmod(0o755 if path.is_dir() else 0o644)
    for path in list(binaries.iterdir()) + [base / 'Applications/Slipstream.app/Slipstream', base / 'Applications/Slipstream.app/PlugIns/AppProxyProvider.appex/AppProxyProvider'] + [control / n for n in ('preinst','postinst','prerm','postrm')]:
        path.chmod(0o755)
    (base / 'Applications/Slipstream.app/slipstream-helper').chmod(0o4755)
    output = ROOT / f'build/{PACKAGE}_{ver}_{arch}.deb'
    subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(stage), str(output)], check=True)
    return output

def repository(output, debs, signing_key):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise ValueError('Repository output directory must be empty')
    pool = output / 'pool'
    pool.mkdir(parents=True, exist_ok=True)
    entries, latest = [], {}
    for deb in map(Path, debs):
        field = lambda name: run('dpkg-deb', '-f', str(deb), name)
        ver, arch = version(field('Version')), field('Architecture')
        if field('Package') != PACKAGE or arch not in ARCHES.values():
            raise ValueError(f'Unexpected package: {deb}')
        name = f'{PACKAGE}_{ver}_{arch}.deb'
        if (pool / name).exists():
            raise ValueError(f'Duplicate package: {name}')
        shutil.copy2(deb, pool / name)
        data = deb.read_bytes()
        entries.append(run('dpkg-deb', '-f', str(deb)) + f'\nFilename: pool/{name}\nSize: {len(data)}\nSHA256: {hashlib.sha256(data).hexdigest()}\nSHA512: {hashlib.sha512(data).hexdigest()}\n\n')
        key = tuple(map(int, ver.split('.')))
        if arch not in latest or key > latest[arch][0]:
            latest[arch] = (key, ver, name)
    if not entries:
        raise ValueError('No packages to index')
    packages = ''.join(entries).encode()
    indexes = {'Packages': packages, 'Packages.gz': gzip.compress(packages, mtime=0), 'Packages.bz2': bz2.compress(packages), 'Packages.xz': lzma.compress(packages)}
    for name, content in indexes.items():
        (output / name).write_bytes(content)
    ver = max(latest.values())[1]
    date = datetime.datetime.now(datetime.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
    release = f'Origin: Slipstream\nLabel: Slipstream\nSuite: stable\nCodename: ios\nVersion: {ver}\nArchitectures: {" ".join(sorted(latest))}\nComponents: main\nDescription: Slipstream packages\nDate: {date}\n'
    for algorithm in ('SHA256', 'SHA512'):
        release += algorithm + ':\n'
        for name, content in indexes.items():
            release += f' {hashlib.new(algorithm.lower(), content).hexdigest()} {len(content)} {name}\n'
    (output / 'Release').write_text(release)
    for args in [('--armor', '--detach-sign', '--output', str(output/'Release.gpg')), ('--clearsign', '--output', str(output/'InRelease'))]:
        subprocess.run(['gpg', '--batch', '--yes', '--digest-algo', 'SHA256', '--local-user', signing_key, *args, str(output/'Release')], check=True)
    shutil.copy2(ROOT / 'packaging/repository-key.gpg', output / 'repository-key.gpg')
    shutil.copy2(ROOT / 'docs/images/icon.png', output / 'CydiaIcon.png')
    keyprint = run('gpg', '--show-keys', '--with-colons', str(output/'repository-key.gpg'))
    fingerprint = next(line.split(':')[9] for line in keyprint.splitlines() if line.startswith('fpr:'))
    safe_url = html.escape(REPO, quote=True)
    summary = 'Send a jailbroken iPhone’s app traffic through your HTTP CONNECT or SOCKS5 proxy, for every app you installed or only the ones you choose.'
    labels = {'iphoneos-arm64': 'Rootless, such as Dopamine or palera1n', 'iphoneos-arm': 'Rootful, such as Taurine'}
    downloads = ''.join(f'<li><a href="pool/{latest[arch][2]}">{labels[arch]}</a></li>' for arch in sorted(latest))
    (output/'index.html').write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Slipstream</title>
<meta name="description" content="{summary}"><meta property="og:title" content="Slipstream"><meta property="og:description" content="{summary}"><meta property="og:image" content="{safe_url}CydiaIcon.png">
<style>:root{{color-scheme:light dark}}body{{font:17px/1.6 system-ui;max-width:42rem;margin:4rem auto;padding:0 1.5rem}}a{{color:light-dark(#0065f0,#4d97ff)}}code{{overflow-wrap:anywhere}}img{{border-radius:22%}}small{{display:block;margin-top:3rem}}</style>
<main><img src="CydiaIcon.png" width="96" height="96" alt=""><h1>Slipstream</h1><p>{summary}</p>
<p><a href="sileo://source/{safe_url}">Add to Sileo</a></p><p>Or add <code>{safe_url}</code> in Sileo → Sources → +.</p>
<p>Version {ver} · iOS 14+ · Rootless and rootful jailbreaks</p>
<p>Download the latest .deb:</p><ul>{downloads}</ul>
<p>Open Slipstream after installation to import and choose a proxy. HTTPS stays end-to-end encrypted. HTTP proxies carry TCP only; SOCKS5 proxies can also relay UDP. Protection requires an active jailbreak.</p>
<details><summary>Repository signing key</summary><p>The package installs the public key for verified updates. For command-line APT, install <a href="repository-key.gpg">this key</a> in <code>/var/jb/etc/apt/trusted.gpg.d/slipstream.gpg</code> (rootful: <code>/etc/apt/trusted.gpg.d/slipstream.gpg</code>) before refreshing.</p><p>Fingerprint: <code>{fingerprint}</code></p></details>
<small><a href="{SOURCE}">Source on GitHub</a> · MIT License · No proxy credentials are included.</small></main></html>''')
    print(f'Repository ready: {output}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('package'); p.add_argument('version')
    p = sub.add_parser('repository'); p.add_argument('output'); p.add_argument('debs', nargs='+'); p.add_argument('--signing-key', required=True)
    args = parser.parse_args()
    if args.command == 'package': print(package(args.version))
    else: repository(args.output, args.debs, args.signing_key)
