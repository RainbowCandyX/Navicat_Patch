import argparse
import json
import os
import plistlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from keychain_compatible import CompatibilityError, check_patch_bytes, digest, operation_lock, read_json, require, run_command, stream_copy, text_digest
from patch_library import ChineseParser, PatchError, load_manifest, validate_file, write_atomic


MACOS_DIRECTORY = Path(__file__).resolve().parents[1]
NATIVE_DIRECTORY = MACOS_DIRECTORY / "native"
SYMBOLS = ("_SecItemAdd", "_SecItemCopyMatching", "_SecItemUpdate", "_SecItemDelete")
SAFE_ENTITLEMENTS = ("com.apple.security.automation.apple-events", "com.apple.security.cs.allow-jit", "com.apple.security.cs.allow-unsigned-executable-memory", "com.apple.security.cs.disable-library-validation")


def read_at(stream, offset, size):
    require(0 <= offset and 0 <= size <= 10 * 1024 * 1024, "Mach-O 读取范围无效或过大")
    stream.seek(offset)
    data = stream.read(size)
    require(len(data) == size, "Mach-O 文件被截断")
    return data


def macho_commands(path):
    with path.open("rb") as stream:
        header = read_at(stream, 0, 32)
        magic, cpu, _, kind, count, size = struct.unpack_from("<IIIIII", header)
        require(magic == 0xFEEDFACF and cpu == 0x100000C and kind == 2, "只支持 arm64 主程序")
        commands = read_at(stream, 32, size)
    result = []
    position = 0
    for _ in range(count):
        require(position + 8 <= len(commands), "加载命令头被截断")
        kind, length = struct.unpack_from("<II", commands, position)
        require(length >= 8 and length % 8 == 0 and position + length <= len(commands), "加载命令长度无效")
        result.append((kind, commands[position:position + length]))
        position += length
    require(position == size, "加载命令总长度不匹配")
    return header, result


def import_slots(path):
    _, commands = macho_commands(path)
    symbols = next((struct.unpack_from("<IIII", data, 8) for kind, data in commands if kind == 2), None)
    indirect = next((struct.unpack_from("<II", data, 56) for kind, data in commands if kind == 11), None)
    require(symbols is not None and indirect is not None, "主程序缺少导入表")
    sections = []
    base = None
    for kind, data in commands:
        if kind != 25:
            continue
        count = struct.unpack_from("<I", data, 64)[0]
        require(len(data) == 72 + count * 80, "段的节表长度无效")
        if data[8:24].split(b"\0")[0] == b"__TEXT":
            base = struct.unpack_from("<Q", data, 24)[0]
        for index in range(count):
            section = data[72 + index * 80:152 + index * 80]
            flags, first = struct.unpack_from("<II", section, 64)
            if flags & 255 == 6:
                address, size = struct.unpack_from("<QQ", section, 32)
                sections.append((address, size, first))
    require(base is not None, "主程序缺少 __TEXT 段")
    symoff, nsyms, stroff, strsize = symbols
    table, count = indirect
    found = {}
    with path.open("rb") as stream:
        for address, size, first in sections:
            require(size % 8 == 0 and first + size // 8 <= count, "间接符号范围无效")
            indices = read_at(stream, table + first * 4, size // 2)
            for position in range(size // 8):
                index = struct.unpack_from("<I", indices, position * 4)[0]
                if index & 0xC0000000:
                    continue
                require(index < nsyms, "间接符号索引越界")
                entry = read_at(stream, symoff + index * 16, 16)
                string = struct.unpack_from("<I", entry)[0]
                require(string < strsize, "符号名称索引越界")
                name = read_at(stream, stroff + string, min(256, strsize - string)).split(b"\0")[0].decode("utf-8")
                if name in SYMBOLS:
                    require(name not in found, "目标 API 存在重复导入指针")
                    found[name] = address + position * 8 - base
    require(set(found) == set(SYMBOLS), "未找到完整的四个钥匙串 API 导入指针")
    return found


def inject_dependency(path, dependency):
    header, commands = macho_commands(path)
    encoded = dependency.encode("utf-8") + b"\0"
    length = (24 + len(encoded) + 7) & ~7
    command = struct.pack("<IIIIII", 12, length, 24, 0, 0, 0) + encoded
    command += bytes(length - len(command))
    count, size = struct.unpack_from("<II", header, 16)
    first_data = path.stat().st_size
    for kind, data in commands:
        if kind == 12:
            offset = struct.unpack_from("<I", data, 8)[0]
            require(data[offset:].split(b"\0")[0] != encoded[:-1], "主程序已经包含此注入依赖")
        if kind == 25:
            sections = struct.unpack_from("<I", data, 64)[0]
            for index in range(sections):
                section = data[72 + index * 80:152 + index * 80]
                offset = struct.unpack_from("<I", section, 48)[0]
                if offset:
                    first_data = min(first_data, offset)
    require(32 + size + length <= first_data, "主程序头部空隙不足，拒绝移动代码或破坏偏移")
    with path.open("r+b") as stream:
        require(read_at(stream, 32 + size, length) == bytes(length), "加载命令后存在非零数据，拒绝覆盖")
        stream.seek(32 + size)
        stream.write(command)
        stream.seek(16)
        stream.write(struct.pack("<II", count + 1, size + length))
        stream.flush()
        os.fsync(stream.fileno())


def config_header(config, slots):
    names = ("ADD", "COPY", "UPDATE", "DELETE")
    lines = ["// 由打包脚本根据精确匹配的主程序导入表生成。", f'#define BRIDGE_ACCESS_GROUP {json.dumps(config["access_group"])}', f'#define BRIDGE_MARKER {json.dumps(config["keychain_marker"])}']
    for name, symbol in zip(names, SYMBOLS):
        lines.append(f"#define BRIDGE_SLOT_{name} {slots[symbol]:#x}ULL")
    return "\n".join(lines) + "\n"


def load_config(path):
    config = read_json(path)
    require(config.get("schema_version") == 1 and config.get("architecture") == "arm64", "不支持的内置注入配置")
    require(re.fullmatch("[0-9a-f]{64}", config["main_sha256"]) is not None, "主程序哈希配置无效")
    for key in ("access_group", "keychain_marker", "bundle_id"):
        require(re.fullmatch(r"[A-Za-z0-9._-]{1,160}", config[key]) is not None, "身份或隔离标记配置无效")
    for key in ("injected_library", "patch_manifest"):
        require(Path(config[key]).name == config[key] and config[key] not in (".", ".."), "配置文件名不能包含目录")
    require(re.fullmatch(r"\d+\.\d+", config["minimum_macos"]) is not None, "最低系统版本无效")
    return config


def compiler_arguments(config, include, output, sources):
    sdk = run_command(["/usr/bin/xcrun", "--show-sdk-path"], timeout=20).stdout.strip()
    arguments = ["/usr/bin/xcrun", "clang", "-arch", config["architecture"], "-isysroot", sdk, "-mmacosx-version-min=" + config["minimum_macos"], "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fvisibility=hidden", "-I", str(include), "-I", str(NATIVE_DIRECTORY)]
    arguments.extend(["-dynamiclib", "-Wl,-install_name,@executable_path/" + config["injected_library"]])
    return arguments + [str(source) for source in sources] + ["-framework", "CoreFoundation", "-framework", "Security", "-o", str(output)]


def prepare(args):
    config_path = args.config.resolve(strict=True)
    config = load_config(config_path)
    manifest, patches = load_manifest(config_path.parent / config["patch_manifest"])
    source = args.source_app.resolve(strict=True)
    output = args.output.resolve()
    require(not output.exists() and output.parent.is_dir(), "输出已存在或父目录不存在")
    require(not any(part.lower().endswith(".app") for part in output.parts), "输出包不能位于应用内")
    info = plistlib.loads((source / "Contents/Info.plist").read_bytes())
    require((info["CFBundleIdentifier"], info["CFBundleShortVersionString"], info["CFBundleVersion"]) == (config["bundle_id"], config["version"], config["build"]), "应用版本与配置不匹配")
    name = info["CFBundleExecutable"]
    require(Path(name).name == name, "主程序名称无效")
    main = source / "Contents/MacOS" / name
    library = source / manifest["target"]
    require(main.resolve().is_relative_to(source) and library.resolve().is_relative_to(source), "输入文件位于应用包之外")
    require(digest(main) == config["main_sha256"], "主程序不是配置指定的原厂文件")
    validate_file(library, manifest, patches)
    run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(source)], timeout=120)
    entitlements_result = run_command(["/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", str(main)])
    entitlements = plistlib.loads(entitlements_result.stdout.encode("utf-8"))
    require(config["access_group"] in entitlements.get("keychain-access-groups", []), "原厂访问组与配置不匹配")
    safe = {key: entitlements[key] for key in SAFE_ENTITLEMENTS if key in entitlements}
    require(safe.get("com.apple.security.cs.disable-library-validation") is True, "原应用未声明允许加载不同签名的库")
    slots = import_slots(main)
    with operation_lock(output.parent / (output.name + ".prepare.lock")):
        require(not output.exists(), "输出已经存在，拒绝覆盖")
        stage = Path(tempfile.mkdtemp(prefix=".navicat-embedded-", dir=output.parent))
        try:
            backup = stage / "backup"
            backup.mkdir(mode=0o700)
            app = stage / source.name
            run_command(["/usr/bin/ditto", "--noqtn", str(source), str(app)], timeout=180)
            copied_main = app / "Contents/MacOS" / name
            copied_core = app / manifest["target"]
            resources = app / "Contents/_CodeSignature/CodeResources"
            for original, saved in ((main, "main"), (library, "libcc.dylib"), (resources, "CodeResources")):
                stream_copy(original, backup / saved)
            write_atomic(library, stage / "patched-core.dylib", manifest["patched_sha256"], patches)
            original_main_text = text_digest(copied_main)
            core_text = text_digest(stage / "patched-core.dylib")
            os.replace(stage / "patched-core.dylib", copied_core)
            header = stage / "bridge_config.h"
            header.write_text(config_header(config, slots), encoding="utf-8")
            injected = app / "Contents/MacOS" / config["injected_library"]
            require(not injected.exists(), "原厂包内已存在同名注入库")
            run_command(compiler_arguments(config, stage, injected, [NATIVE_DIRECTORY / "keychain_bridge.c"]), timeout=120)
            inject_dependency(copied_main, "@executable_path/" + config["injected_library"])
            require(text_digest(copied_main) == original_main_text, "注入改变了主程序代码节")
            signing = stage / "runtime-entitlements.plist"
            signing.write_bytes(plistlib.dumps(safe))
            for path in (copied_core, injected):
                run_command(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", str(path)])
            run_command(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none", "--options", "runtime", "--entitlements", str(signing), str(app)])
            run_command(["/usr/bin/xattr", "-dr", "com.apple.quarantine", str(app)])
            run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=120)
            check_patch_bytes(copied_core, manifest)
            require(text_digest(copied_core) == core_text and text_digest(copied_main) == original_main_text, "签名改变了代码节")
            package = {"schema_version": 1, "app": source.name, "executable_name": name, "core": manifest["target"], "injected_library": config["injected_library"], "version": config["version"], "build": config["build"], "keychain_marker": config["keychain_marker"], "slots": slots, "files": {}, "backups": {}}
            for path in (copied_main, copied_core, injected):
                package["files"][str(path.relative_to(stage))] = digest(path)
            for path in backup.iterdir():
                package["backups"][str(path.relative_to(stage))] = digest(path)
            (stage / "embedded-package.json").write_text(json.dumps(package, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.rename(stage, output)
        except BaseException:
            shutil.rmtree(stage)
            raise
    print(json.dumps({"状态": "内置注入包已生成", "应用": str(output / source.name), "启动方式": "可直接打开主程序或双击 app，不需要动态库环境变量", "五处功能修改": "代码节与补丁字节验证通过", "钥匙串保存实测": "等待用户验证", "原安装": "未修改"}, ensure_ascii=False))


def checked_file(root, relative):
    path = root / relative
    require(not Path(relative).is_absolute() and path.resolve().is_relative_to(root) and not path.is_symlink(), "包内文件路径不安全")
    return path


def load_package(directory):
    root = directory.resolve(strict=True)
    require(root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o022 == 0, "包目录权限不安全")
    config = read_json(root / "embedded-package.json")
    require(config.get("schema_version") == 1, "内置包配置版本无效")
    for relative, expected in {**config["files"], **config["backups"]}.items():
        require(digest(checked_file(root, relative)) == expected, "内置包文件或备份哈希不匹配")
    app = checked_file(root, config["app"])
    run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=120)
    return root, config, app


def launch(args):
    _, config, app = load_package(args.package)
    running = subprocess.run(["/usr/bin/pgrep", "-x", re.escape(config["executable_name"])], capture_output=True, text=True, encoding="utf-8", timeout=10, check=False)
    require(running.returncode == 1, "Navicat 已在运行或进程检查失败，请先正常退出")
    environment = {key: value for key, value in os.environ.items() if not key.startswith("DYLD_")}
    main = app / "Contents/MacOS" / config["executable_name"]
    process = subprocess.Popen([str(main)], env=environment, cwd=main.parent, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        require(process.poll() is None, f"主程序启动后退出，退出码={process.returncode}")
        files = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(process.pid), "-Fn"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5, check=False)
        paths = set(line[1:] for line in files.stdout.splitlines() if line.startswith("n"))
        if str(main.parent / config["injected_library"]) in paths and str(app / config["core"]) in paths:
            print(json.dumps({"状态": "直接启动成功，已确认内置注入库和补丁核心库加载", "PID": process.pid, "应用": str(app), "动态库环境变量": "未使用", "保存密码实测": "等待用户验证"}, ensure_ascii=False))
            return
        time.sleep(0.2)
    raise CompatibilityError(f"尚未确认全部内置库加载；应用 PID={process.pid}，请正常退出后检查")


def restore(args):
    root, config, app = load_package(args.package)
    output = args.output.resolve()
    require(not output.exists() and output.parent.is_dir(), "还原输出已存在或父目录不存在")
    with operation_lock(output.parent / (output.name + ".restore.lock")):
        stage = Path(tempfile.mkdtemp(prefix=".navicat-restore-", dir=output.parent))
        try:
            restored = stage / app.name
            run_command(["/usr/bin/ditto", str(app), str(restored)], timeout=180)
            targets = (("main", restored / "Contents/MacOS" / config["executable_name"]), ("libcc.dylib", restored / config["core"]), ("CodeResources", restored / "Contents/_CodeSignature/CodeResources"))
            for saved, destination in targets:
                temporary = stage / (saved + ".restore")
                stream_copy(root / "backup" / saved, temporary)
                os.replace(temporary, destination)
            (restored / "Contents/MacOS" / config["injected_library"]).unlink()
            run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(restored)], timeout=120)
            os.rename(stage, output)
        except BaseException:
            shutil.rmtree(stage)
            raise
    print(f"已还原原厂签名应用副本：{output / app.name}；未修改原安装或钥匙串。")


def main():
    parser = ChineseParser(description="内置注入与本地钥匙串转接：生成独立应用，保留原安装和可校验备份")
    commands = parser.add_subparsers(dest="action", required=True)
    prepare_parser = commands.add_parser("prepare", help="编译注入库并生成可直接打开的独立应用")
    prepare_parser.add_argument("--config", type=Path, default=MACOS_DIRECTORY / "embedded-config.json")
    prepare_parser.add_argument("--source-app", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    for action in ("check", "launch", "restore"):
        command = commands.add_parser(action)
        command.add_argument("--package", type=Path, required=True)
        if action == "restore":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            prepare(args)
        elif args.action == "restore":
            restore(args)
        elif args.action == "launch":
            launch(args)
        else:
            _, _, app = load_package(args.package)
            print(f"内置包哈希和整包签名校验通过：{app}")
        return 0
    except (CompatibilityError, PatchError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"操作失败：{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
