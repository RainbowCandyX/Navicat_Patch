import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from macho_readonly import inspect_layout


CHUNK_SIZE = 1024 * 1024


class CompatibilityError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise CompatibilityError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(CHUNK_SIZE):
            result.update(data)
    return result.hexdigest()


def read_json(path):
    require(path.stat().st_size <= CHUNK_SIZE, "配置或清单超过大小上限")
    return json.loads(path.read_text(encoding="utf-8"))


def run_command(arguments, timeout=60):
    result = subprocess.run(arguments, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False)
    if result.returncode != 0:
        raise CompatibilityError(f"外部工具失败，退出码={result.returncode}: {arguments[0]}\n{result.stderr[-3000:]}")
    return result


def read_entitlements(executable):
    result = run_command(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(executable)])
    require("<?xml" in result.stdout, "主程序没有可读取的原厂 entitlement")
    return plistlib.loads(result.stdout[result.stdout.index("<?xml"):].encode("utf-8"))


def check_host(executable, expected_hash, expected_group=None):
    require(digest(executable) == expected_hash, "主程序已变化，拒绝使用未知或重新签名的宿主")
    run_command(["/usr/bin/codesign", "--verify", "--strict", str(executable)])
    entitlements = read_entitlements(executable)
    team = entitlements.get("com.apple.developer.team-identifier")
    groups = entitlements.get("keychain-access-groups", [])
    require(isinstance(team, str) and bool(team), "主程序缺少团队标识")
    require(entitlements.get("com.apple.security.cs.allow-dyld-environment-variables") is True, "原厂主程序不允许动态库路径变量")
    require(entitlements.get("com.apple.security.cs.disable-library-validation") is True, "原厂主程序未授权加载不同签名的动态库")
    require(isinstance(groups, list) and bool(groups), "原厂主程序缺少钥匙串访问组")
    if expected_group is not None:
        require(expected_group in groups, "原厂主程序未声明配置中的钥匙串访问组")
    details = run_command(["/usr/bin/codesign", "-dv", "--verbose=4", str(executable)])
    require("Signature=adhoc" not in details.stderr and f"TeamIdentifier={team}" in details.stderr, "主程序不是匹配团队的原厂签名")
    return entitlements


def stream_copy(source, destination):
    with source.open("rb") as reader, destination.open("xb") as writer:
        shutil.copyfileobj(reader, writer, CHUNK_SIZE)
        writer.flush()
        os.fsync(writer.fileno())
    destination.chmod(stat.S_IMODE(source.stat().st_mode) & 0o755)


def text_digest(path):
    _, sections, _ = inspect_layout(path)
    _, _, size, offset = next(section for section in sections if section[0] == "__text")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        while size:
            data = stream.read(min(CHUNK_SIZE, size))
            require(bool(data), "代码节被截断")
            result.update(data)
            size -= len(data)
    return result.hexdigest()


def check_patch_bytes(path, manifest):
    with path.open("rb") as stream:
        for item in manifest["patches"]:
            expected = bytes.fromhex(item["after"])
            stream.seek(item["offset"])
            require(stream.read(len(expected)) == expected, f"补丁字节丢失: {item['virtual_address']}")


@contextlib.contextmanager
def operation_lock(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise CompatibilityError("相同目录已有打包或启动操作") from error
        yield
    finally:
        os.close(descriptor)


def prepare(args):
    source_app = args.source_app.resolve(strict=True)
    original = args.original_library.resolve(strict=True)
    patched = args.patched_library.resolve(strict=True)
    output = args.output.resolve()
    require(not output.exists(), "输出目录已经存在，拒绝覆盖")
    require(output.parent.is_dir(), "输出父目录不存在")
    require(not any(part.lower().endswith(".app") for part in output.parts), "打包目录不能位于应用包内")
    manifest = read_json(args.manifest)
    require(digest(original) == manifest["original_sha256"], "原始库备份哈希不匹配")
    require(digest(patched) == manifest["patched_sha256"], "补丁库哈希不匹配")
    info = plistlib.loads((source_app / "Contents/Info.plist").read_bytes())
    executable_name = info["CFBundleExecutable"]
    require(Path(executable_name).name == executable_name, "主程序名称不是单个文件名")
    executable = source_app / "Contents/MacOS" / executable_name
    entitlements = check_host(executable, args.expected_main_sha256)
    access_group = args.access_group
    require(access_group.startswith(info["AppIdentifierPrefix"]), "钥匙串访问组与原厂前缀不匹配")
    require(access_group in entitlements["keychain-access-groups"], "实际钥匙串访问组不在原厂 entitlement 中")
    with operation_lock(output.parent / (output.name + ".prepare.lock")):
        require(not output.exists(), "输出目录已经存在，拒绝覆盖")
        stage = Path(tempfile.mkdtemp(prefix=".keychain-compatible-", dir=output.parent))
        try:
            host_parent = stage / "host"
            host_parent.mkdir(mode=0o700)
            host_app = host_parent / source_app.name
            # 只复制程序包，不复制用户配置；原安装目录不作任何修改。
            run_command(["/usr/bin/ditto", str(source_app), str(host_app)], timeout=180)
            host_library = host_app / manifest["target"]
            temporary = host_library.with_name(host_library.name + ".restore")
            stream_copy(original, temporary)
            os.replace(temporary, host_library)
            require(digest(host_library) == manifest["original_sha256"], "宿主副本的原厂库恢复失败")
            run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(host_app)], timeout=120)
            copied_main = host_app / "Contents/MacOS" / executable_name
            check_host(copied_main, args.expected_main_sha256, access_group)
            libraries = stage / "libraries"
            libraries.mkdir(mode=0o700)
            override = libraries / "libcc.dylib"
            stream_copy(patched, override)
            # 只签外置补丁库，绝不重签宿主或主程序。
            run_command(["/usr/bin/codesign", "--force", "--sign", "-", str(override)])
            run_command(["/usr/bin/codesign", "--verify", "--strict", str(override)])
            check_patch_bytes(override, manifest)
            require(text_digest(override) == text_digest(patched), "单独签名改变了补丁库代码节")
            profile = host_app / "Contents/embedded.provisionprofile"
            config = {
                "schema_version": 1,
                "app": str(output / "host" / source_app.name),
                "executable_name": executable_name,
                "main_sha256": args.expected_main_sha256,
                "original_library_sha256": manifest["original_sha256"],
                "library": str(output / "libraries/libcc.dylib"),
                "library_sha256": digest(override),
                "profile_sha256": digest(profile),
                "access_group": access_group,
                "version": info["CFBundleShortVersionString"],
                "build": info["CFBundleVersion"],
            }
            (stage / "launch-config.json").write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.rename(stage, output)
        except BaseException:
            shutil.rmtree(stage)
            raise
    print(json.dumps({"状态": "打包完成", "目录": str(output), "宿主签名": "原厂完整签名验证通过", "外置补丁库": "单独签名验证通过，全部原补丁字节及代码节保持不变", "钥匙串访问组": access_group, "保存密码实测": "未验证"}, ensure_ascii=False))


def load_package(directory):
    root = directory.resolve(strict=True)
    require(root.stat().st_uid == os.getuid(), "打包目录不属于当前用户")
    require(root.stat().st_mode & 0o022 == 0, "打包目录可被其他用户写入")
    config = read_json(root / "launch-config.json")
    require(config.get("schema_version") == 1, "不支持的启动配置版本")
    app = Path(config["app"])
    library = Path(config["library"])
    require(app.resolve().parent == root / "host", "宿主路径超出打包目录")
    require(library.resolve() == root / "libraries/libcc.dylib", "补丁库路径超出打包目录")
    require(not library.is_symlink(), "补丁库不能是符号链接")
    require(library.parent.stat().st_uid == os.getuid() and library.parent.stat().st_mode & 0o022 == 0, "动态库目录权限不安全")
    require(digest(library) == config["library_sha256"], "外置补丁库被改动，拒绝启动")
    require(digest(app / "Contents/Frameworks/libcc.dylib") == config["original_library_sha256"], "宿主内的原厂库被改动")
    require(digest(app / "Contents/embedded.provisionprofile") == config["profile_sha256"], "原厂 provisioning profile 被改动")
    check_host(app / "Contents/MacOS" / config["executable_name"], config["main_sha256"], config["access_group"])
    run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=120)
    run_command(["/usr/bin/codesign", "--verify", "--strict", str(library)])
    return root, config, app, library


def launch(args):
    root, config, app, library = load_package(args.package)
    with operation_lock(root / "launch.lock"):
        running = subprocess.run(["/usr/bin/pgrep", "-x", re.escape(config["executable_name"])], capture_output=True, text=True, encoding="utf-8", timeout=10, check=False)
        require(running.returncode in (0, 1), "无法检查已有应用进程")
        require(running.returncode == 1, "Navicat 已在运行，请先正常退出，避免两个实例同时修改连接配置")
        environment = {key: value for key, value in os.environ.items() if not key.startswith("DYLD_")}
        environment["DYLD_LIBRARY_PATH"] = str(library.parent)
        loader_log = root / "runtime-loader.log"
        if args.diagnose:
            require(not loader_log.is_symlink(), "加载日志不能是符号链接")
            descriptor = os.open(loader_log, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(descriptor)
            environment["DYLD_PRINT_LIBRARIES"] = "1"
            environment["DYLD_PRINT_TO_FILE"] = str(loader_log)
        executable = app / "Contents/MacOS" / config["executable_name"]
        process = subprocess.Popen([str(executable)], env=environment, cwd=executable.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        if args.diagnose:
            deadline = time.monotonic() + 20
            matched = None
            with loader_log.open("r", encoding="utf-8", errors="replace") as stream:
                while time.monotonic() < deadline:
                    for line in stream:
                        if str(library) in line:
                            matched = line.strip()
                    if process.poll() is not None:
                        raise CompatibilityError(f"应用启动后退出，退出码={process.returncode}；未声称保存密码已修复")
                    if matched is not None:
                        break
                    time.sleep(0.1)
            require(matched is not None, f"尚未确认外置补丁库已加载；应用进程 PID={process.pid}，请正常退出后检查日志")
            print(json.dumps({"状态": "已确认加载外置补丁库", "PID": process.pid, "库路径": str(library), "加载证据": matched, "宿主签名": "原厂签名保持不变", "保存密码实测": "等待仅含测试数据的界面验证"}, ensure_ascii=False))
        else:
            print(json.dumps({"状态": "已启动", "PID": process.pid, "保存密码实测": "未验证"}, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(description="保留原厂签名宿主，通过原厂允许的动态库路径加载外置补丁")
    commands = parser.add_subparsers(dest="action", required=True)
    prepare_parser = commands.add_parser("prepare", help="生成独立兼容包，不修改安装目录")
    prepare_parser.add_argument("--source-app", type=Path, required=True)
    prepare_parser.add_argument("--original-library", type=Path, required=True)
    prepare_parser.add_argument("--patched-library", type=Path, required=True)
    prepare_parser.add_argument("--manifest", type=Path, required=True)
    prepare_parser.add_argument("--expected-main-sha256", required=True)
    prepare_parser.add_argument("--access-group", required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    launch_parser = commands.add_parser("launch", help="校验兼容包并启动原厂签名宿主")
    launch_parser.add_argument("--package", type=Path, required=True)
    launch_parser.add_argument("--diagnose", action="store_true", help="只记录动态库加载路径并确认补丁库被加载")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            require(re.fullmatch("[0-9a-f]{64}", args.expected_main_sha256) is not None, "主程序哈希格式无效")
            prepare(args)
        else:
            launch(args)
        return 0
    except (CompatibilityError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"操作失败: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
