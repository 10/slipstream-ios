#!/usr/bin/env python3
"""Verify the built archive's privilege boundary, contents, and runtime dependencies."""
import io
import plistlib
import subprocess
import sys
import tarfile

path = sys.argv[1]
field = lambda name: subprocess.check_output(['dpkg-deb','-f',path,name],text=True).strip()
assert field('Package') == 'io.github.10.slipstream'
# Rootless packages install under var/jb; rootful ones at the filesystem root.
root = {'iphoneos-arm64': 'var/jb/', 'iphoneos-arm': ''}[field('Architecture')]
assert 'firmware (>= 14.0)' in field('Depends')
# Earlier uicache registers the app proxy provider without its entitlements.
assert 'uikittools (>= 2.1.2)' in field('Depends')
data = subprocess.check_output(['dpkg-deb','--fsys-tarfile',path])
with tarfile.open(fileobj=io.BytesIO(data)) as archive:
    files = {m.name.removeprefix('./'): m for m in archive.getmembers()}
    for name, member in files.items():
        assert member.uid == member.gid == 0, name
        assert not member.issym() and not member.islnk(), name
        assert not name.startswith((root+'etc/slipstream/', root+'var/')), name
        if member.isfile():
            assert member.mode & 0o022 == 0, name
            # A rootful package built with any rootless part would run nothing.
            assert root or b'/var/jb' not in archive.extractfile(member).read(), name
    helper = root+'Applications/Slipstream.app/slipstream-helper'
    assert files[helper].mode == 0o4755
    assert [name for name,m in files.items() if m.mode & 0o6000] == [helper]
    for name in ('slipstream','slipstreamctl'):
        assert files[root+'usr/local/bin/'+name].mode == 0o755
    subprocess.run(['sh', '-n'], input=archive.extractfile(files[root+'usr/local/bin/slipstreamctl']).read(), check=True)
    extension = root+'Applications/Slipstream.app/PlugIns/AppProxyProvider.appex/'
    assert files[extension+'AppProxyProvider'].mode == 0o755
    provider = plistlib.load(archive.extractfile(files[extension+'Info.plist']))
    assert provider['CFBundleIdentifier'] == 'local.slipstream.app.proxy'
    assert provider['CFBundleVersion'] == field('Version')
    assert provider['NSExtension']['NSExtensionPointIdentifier'] == 'com.apple.networkextension.app-proxy'

    info = plistlib.load(archive.extractfile(files[root+'Applications/Slipstream.app/Info.plist']))
    assert info['CFBundleShortVersionString'] == field('Version')
    assert info['MinimumOSVersion'] == provider['MinimumOSVersion'] == '14.0'
    assert root+'etc/apt/trusted.gpg.d/slipstream.gpg' in files
    assert root+'usr/share/doc/io.github.10.slipstream/copyright' in files
control = subprocess.check_output(['dpkg-deb','--ctrl-tarfile',path])
with tarfile.open(fileobj=io.BytesIO(control)) as archive:
    for name in ('preinst','postinst','prerm','postrm'):
        member = archive.getmember('./'+name)
        assert member.mode == 0o755
        script = archive.extractfile(member).read()
        assert b'@SCRIPT@' not in script
        subprocess.run(['sh', '-n'], input=script, check=True)
        assert root or b'/var/jb' not in script
        assert script.startswith(f'#!/{root}bin/sh\n'.encode())
print('Package contents, root ownership, helper permissions, and version passed.')
