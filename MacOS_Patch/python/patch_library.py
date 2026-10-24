import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


class PatchError(Exception):
    pass


class ChineseParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, "参数无效，请按 --help 中的用法提供参数。\n")


def load_manifest(path):
    if path.stat().st_size > CHUNK_SIZE:
        raise PatchError("补丁清单超过大小上限")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise PatchError("补丁清单必须是 JSON 对象")
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("size"), int) or manifest["size"] <= 0:
        raise PatchError("补丁清单版本或文件大小无效")
    for key in ("original_sha256", "patched_sha256"):
        if not isinstance(manifest.get(key), str) or not re.fullmatch("[0-9a-f]{64}", manifest[key]):
            raise PatchError("补丁清单中的哈希无效")
    patches = []
    previous_end = 0
    for item in manifest.get("patches", []):
        before = bytes.fromhex(item["before"])
        after = bytes.fromhex(item["after"])
        offset = item["offset"]
        if not isinstance(offset, int) or offset < previous_end or not before or len(before) != len(after):
            raise PatchError("补丁范围重叠、顺序错误或长度不一致")
        if len(before) > CHUNK_SIZE or offset + len(before) > manifest["size"] or before == after:
            raise PatchError("补丁超出文件范围或没有实际变更")
        patches.append((offset, before, after))
        previous_end = offset + len(before)
    if not patches:
        raise PatchError("清单中没有补丁")
    return manifest, patches


def chunks(path, patches=()):
    with path.open("rb") as stream:
        position = 0
        while data := stream.read(CHUNK_SIZE):
            for offset, before, after in patches:
                left = max(position, offset)
                right = min(position + len(data), offset + len(before))
                if left < right:
                    data = data[:left - position] + after[left - offset:right - offset] + data[right - position:]
            yield data
            position += len(data)


def digest(path, patches=()):
    result = hashlib.sha256()
    for data in chunks(path, patches):
        result.update(data)
    return result.hexdigest()


def validate_file(path, manifest, patches, patched=False):
    expected_hash = manifest["patched_sha256" if patched else "original_sha256"]
    if not path.is_file() or path.stat().st_size != manifest["size"]:
        raise PatchError("文件不存在或大小与清单不匹配")
    if digest(path) != expected_hash:
        raise PatchError("文件哈希不匹配，拒绝修改")
    with path.open("rb") as stream:
        for offset, before, after in patches:
            expected = after if patched else before
            stream.seek(offset)
            if stream.read(len(expected)) != expected:
                raise PatchError(f"偏移 {offset:#x} 的字节不匹配")


def external_destination(path):
    if path.is_symlink():
        raise PatchError("输出和备份不能是符号链接")
    resolved = path.resolve()
    if any(part.lower().endswith(".app") for part in resolved.parts):
        raise PatchError("只允许在 app 包外生成离线文件，不允许直接修改已安装应用")
    if not resolved.parent.is_dir():
        raise PatchError("输出目录不存在")
    return resolved


@contextlib.contextmanager
def output_lock(output):
    lock = output.with_name(output.name + ".lock")
    descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PatchError("同一输出文件已有补丁操作正在执行") from error
        yield
    finally:
        os.close(descriptor)


def write_atomic(source, destination, expected_hash, patches=(), replace_hash=None):
    descriptor, temporary_name = tempfile.mkstemp(prefix=".navicat-patch-", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), stat.S_IMODE(source.stat().st_mode) & 0o777)
            result = hashlib.sha256()
            for data in chunks(source, patches):
                stream.write(data)
                result.update(data)
            stream.flush()
            os.fsync(stream.fileno())
        if result.hexdigest() != expected_hash:
            raise PatchError("生成文件的哈希不符合预期，未发布输出")
        if replace_hash is None:
            # 使用硬链接发布，已存在的输出不会被覆盖。
            os.link(temporary, destination)
        else:
            if destination.is_symlink() or digest(destination) != replace_hash:
                raise PatchError("输出已被其他操作改变，拒绝覆盖")
            os.replace(temporary, destination)
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def run(action, manifest_path, source=None, output=None, backup=None):
    manifest, patches = load_manifest(manifest_path)
    if action in ("check", "apply"):
        if source is None:
            raise PatchError("此操作需要 --source")
        source = source.resolve(strict=True)
        validate_file(source, manifest, patches)
        if digest(source, patches) != manifest["patched_sha256"]:
            raise PatchError("替换结果与清单中的目标哈希不一致")
        if action == "check":
            return "校验通过：文件大小、原始哈希、原字节和预期结果哈希均匹配；未写入任何文件。"
    if output is None or backup is None:
        raise PatchError("写入和回滚操作需要 --output 与 --backup")
    output, backup = external_destination(output), external_destination(backup)
    if output == backup or source in (output, backup):
        raise PatchError("输入、输出和备份必须是不同路径")
    with output_lock(output):
        if action == "apply":
            if output.exists() or backup.exists():
                raise PatchError("输出或备份已存在，拒绝覆盖")
            write_atomic(source, backup, manifest["original_sha256"])
            write_atomic(source, output, manifest["patched_sha256"], patches)
            validate_file(output, manifest, patches, patched=True)
            return f"已生成离线库: {output}\n原始备份: {backup}\n安装目录未修改；输出库原代码签名已失效，完整 app 运行效果未验证。"
        if action == "rollback":
            validate_file(backup, manifest, patches)
            if output.is_file() and digest(output) == manifest["original_sha256"]:
                return "输出已经是原始文件，无需再次回滚。"
            validate_file(output, manifest, patches, patched=True)
            write_atomic(backup, output, manifest["original_sha256"], replace_hash=manifest["patched_sha256"])
            validate_file(output, manifest, patches)
            return f"已回滚离线库并确认原始哈希: {output}"
    raise PatchError("不支持的操作")


def main():
    parser = ChineseParser(description="离线库补丁工具：流式校验、原件备份、原子发布和精确回滚，不修改 app 包")
    parser.add_argument("action", choices=("check", "apply", "rollback"), help="校验、生成补丁副本或回滚副本")
    parser.add_argument("--manifest", type=Path, required=True, help="补丁清单路径")
    parser.add_argument("--source", type=Path, help="原始库文件路径")
    parser.add_argument("--output", type=Path, help="app 包外的离线输出路径")
    parser.add_argument("--backup", type=Path, help="app 包外的原始备份路径")
    args = parser.parse_args()
    try:
        print(run(args.action, args.manifest, args.source, args.output, args.backup))
        return 0
    except PatchError as error:
        print(f"操作失败: {error}", file=sys.stderr)
    except (ValueError, KeyError, TypeError, UnicodeError):
        print("操作失败：清单内容或编码无效。", file=sys.stderr)
    except OSError as error:
        print(f"文件操作失败：路径={error.filename}，errno={error.errno}。已生成的备份不会自动删除。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
