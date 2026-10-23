"""Build the Android bridge without installing it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--build-tools', default='35.0.0')
    parser.add_argument('--platform', default='android-35')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--keystore', type=Path, required=True,
        help='New or existing LOCAL research signing key; never a vendor key')
    args = parser.parse_args()
    jdk, sdk, out = args.jdk.resolve(), args.sdk.resolve(), args.out.resolve()
    tools = sdk / 'build-tools' / args.build_tools
    android = sdk / 'platforms' / args.platform / 'android.jar'
    source = ROOT / 'minimal_client/bench_android'
    key = args.keystore.resolve()
    for path in [jdk / 'bin/javac', jdk / 'bin/keytool', tools / 'd8', tools / 'aapt2',
                 tools / 'zipalign', tools / 'apksigner', android]:
        if not path.is_file():
            parser.error('Missing build prerequisite: ' + str(path))
    os.umask(0o077)
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    environment = dict(os.environ, JAVA_HOME=str(jdk),
        PATH=str(jdk / 'bin') + os.pathsep + os.environ.get('PATH', ''))

    def run(*values):
        subprocess.run([str(v) for v in values], check=True, env=environment, timeout=120)

    if not key.exists():
        key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        run(jdk / 'bin/keytool', '-genkeypair', '-noprompt', '-keystore', key,
            '-storepass', 'android', '-keypass', 'android', '-alias', 'research',
            '-keyalg', 'RSA', '-keysize', '2048', '-validity', '3650',
            '-dname', 'CN=Local Research Bridge')
        key.chmod(0o600)
    classes, dex = out / 'classes', out / 'dex'
    classes.mkdir(); dex.mkdir()
    run(jdk / 'bin/javac', '-source', '8', '-target', '8', '-bootclasspath', android,
        '-d', classes, source / 'MainActivity.java')
    run(tools / 'd8', '--min-api', '33', '--lib', android, '--output', dex,
        *sorted(classes.rglob('*.class')))
    unsigned, aligned, signed = (out / n for n in ['unsigned.apk', 'aligned.apk', 'bench-client.apk'])
    run(tools / 'aapt2', 'link', '-I', android, '--manifest', source / 'AndroidManifest.xml', '-o', unsigned)
    with zipfile.ZipFile(unsigned, 'a') as archive:
        archive.write(dex / 'classes.dex', 'classes.dex')
    run(tools / 'zipalign', '-f', '4', unsigned, aligned)
    run(tools / 'apksigner', 'sign', '--ks', key, '--ks-key-alias', 'research',
        '--ks-pass', 'pass:android', '--key-pass', 'pass:android', '--out', signed, aligned)
    run(tools / 'apksigner', 'verify', signed)
    record = {'apk': signed.name, 'sha256': hashlib.sha256(signed.read_bytes()).hexdigest(),
        'sources_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.iterdir() if p.is_file()}, 'installed': False,
        'device_tested': False, 'signing_key_is_local_research_only': True}
    (out / 'build-record.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'built': True, 'installed': False, 'apk': str(signed)}))


if __name__ == '__main__':
    main()
