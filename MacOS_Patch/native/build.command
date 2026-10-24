#!/bin/zsh
set -euo pipefail

if (( $# > 1 )); then
    print -u2 -- '参数错误：只接受一个可选的输出目录。'
    exit 2
fi
if [[ "${1:-}" == '--help' || "${1:-}" == '-h' ]]; then
    print -- '用法：build.command [输出目录]'
    print -- '默认输出到 MacOS_Patch/output/native-build，仅编译独立 dylib，不签名、不安装、不修改 app。'
    exit 0
fi

native_dir="${0:A:h}"
macos_dir="${native_dir:h}"
config="${macos_dir}/embedded-config.json"
output_dir="${1:-${macos_dir}/output/native-build}"
output_dir="${output_dir:A}"

case "${output_dir:l}/" in
    *.app/*)
        print -u2 -- '拒绝编译：输出目录不能位于 app 包内。'
        exit 1
        ;;
esac

for source_file in keychain_bridge.c keychain_bridge.h bridge_config.h; do
    if [[ ! -f "${native_dir}/${source_file}" ]]; then
        print -u2 -- "缺少原生源文件：${native_dir}/${source_file}"
        exit 1
    fi
done
if [[ ! -f "$config" ]]; then
    print -u2 -- "缺少配置文件：${config}"
    exit 1
fi

architecture=$(/usr/bin/plutil -extract architecture raw -o - "$config")
minimum_macos=$(/usr/bin/plutil -extract minimum_macos raw -o - "$config")
library_name=$(/usr/bin/plutil -extract injected_library raw -o - "$config")
if [[ "$architecture" != arm64 || "$minimum_macos" != <->.<-> || "$library_name" != *.dylib || "$library_name" == */* || "$library_name" == *[^A-Za-z0-9._-]* ]]; then
    print -u2 -- '配置无效：仅支持 arm64、数字系统版本和不带目录的 dylib 文件名。'
    exit 1
fi

destination="${output_dir}/${library_name}"
if [[ -e "$destination" || -L "$destination" ]]; then
    print -u2 -- "输出已存在，拒绝覆盖：${destination}"
    exit 1
fi
if ! sdk=$(/usr/bin/xcrun --show-sdk-path); then
    print -u2 -- '无法定位 macOS SDK，请先安装并配置 Apple Command Line Tools。'
    exit 1
fi

/bin/mkdir -p -- "$output_dir"
temporary_dir=$(/usr/bin/mktemp -d "${output_dir}/.native-build.XXXXXXXX")
trap 'if [[ -d "$temporary_dir" ]]; then /bin/rm -r -- "$temporary_dir"; fi' EXIT

print -- '开始编译原生钥匙串兼容库，不修改已安装 app。'
if ! /usr/bin/xcrun clang -arch "$architecture" -isysroot "$sdk" "-mmacosx-version-min=${minimum_macos}" -std=c11 -O2 -Wall -Wextra -Werror -fvisibility=hidden -dynamiclib -I "$native_dir" "${native_dir}/keychain_bridge.c" -framework CoreFoundation -framework Security "-Wl,-install_name,@executable_path/${library_name}" -o "${temporary_dir}/${library_name}"; then
    print -u2 -- '编译失败，未发布成品；请查看上面的编译器诊断。'
    exit 1
fi

/bin/ln -- "${temporary_dir}/${library_name}" "$destination"
/usr/bin/shasum -a 256 "$destination"
print -- "编译完成：${destination}"
print -- '使用现有 bridge_config.h；未进行签名、主程序注入、核心库修改或安装。'
