"""Repo-only, offline Helm render fixture; never fetch charts or read customer inputs."""
import hashlib
import io
from pathlib import Path, PurePosixPath
import shutil
import tarfile


SOURCE_FILES = {"helmfile.yaml.gotmpl", "release.yaml", "defaults/values.yaml",
                "examples/values.yaml", "tests/fixtures/values.secrets.yaml"}
LOCAL_CHARTS = {"artifact-publisher", "clickhouse", "ecr-pull-secret-refresh", "postgresql-bootstrap"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_source_files(root, destination, files):
    if len(files) != 42 or len(set(files)) != len(files):
        raise ValueError("render source inventory mismatch")
    for filename in files:
        path = PurePosixPath(filename)
        if (path.is_absolute() or any(part in ("..", ".") for part in path.parts)
                or not (filename in SOURCE_FILES
                        or (len(path.parts) == 2 and path.parts[0] == "values" and path.suffix == ".gotmpl")
                        or (len(path.parts) >= 2 and path.parts[0] == "charts" and path.parts[1] in LOCAL_CHARTS))):
            raise ValueError("unsafe render source inventory")
        source = root.joinpath(*path.parts)
        if (not source.is_file() or source.is_symlink() or any((root / parent).is_symlink()
                for parent in source.relative_to(root).parents if parent != Path('.'))):
            raise ValueError("missing or linked render source file")
        target = destination.joinpath(*path.parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        target.chmod(0o600)


def extract(archive, destination, prefix):
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 100 * 1024 * 1024:
            raise ValueError("chart archive member limit")
        seen = set()
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or not path.parts or any(part in ("..", ".") for part in path.parts)
                    or path.parts[0] != prefix or not (member.isfile() or member.isdir()) or path in seen):
                raise ValueError("unsafe or duplicate chart archive member")
            seen.add(path)
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with bundle.extractfile(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 65536)
                target.chmod(0o600)
