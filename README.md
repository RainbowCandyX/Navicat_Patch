# Navicat_Patch

包含 Windows x64 代理补丁，以及 macOS arm64 原生源码、Python 制作工具与维护说明。macOS 文档统一维护在本文件，不再单独维护 `MacOS_Patch/README.md`。

## Windows

适用于 **Navicat Premium 17 / 18（x64）** 的 `winmm.dll` 代理补丁。

### 功能

- 转发系统 WinMM 导出，保留原有接口。
- 通过特征码定位，在内存中修改试用时间检查和版本状态。
- 成功时不弹窗，仅在失败时使用 `MessageBoxW` 提示。
- 不修改磁盘上的 EXE 和 DLL；特征或原始字节不匹配时不应用补丁。

### 使用

1. 使用 Visual Studio 打开工程，选择 `Release | x64`，生成 `winmm.dll`。
2. 关闭 Navicat，备份安装目录中已有的同名 DLL。
3. 将生成的 `winmm.dll` 放入 `navicat.exe` 所在目录，然后启动 Navicat。

### 还原

关闭 Navicat，移除部署的补丁 DLL；如果原目录已有 `winmm.dll`，恢复之前的备份。

## macOS

仅支持 **Navicat Premium 18.0.3 / build 317 / arm64**，需要 **Python 3.9 及以上**和 Apple Command Line Tools。Python 脚本直接运行，无需编译或安装 pip 依赖。

以下命令均从项目根目录执行。保留完整的 `MacOS_Patch` 目录，不单独复制其中的脚本或源码。

### 1. 安装官方原版

1. 使用匹配版本的官方安装包，将完整 app 安装到 Finder 的“应用程序”目录。
2. 正常退出所有 Navicat 实例。
3. 将未修改的完整 `Navicat Premium.app` 复制到项目根目录，作为脚本输入。不要使用已应用补丁的 app。

尚未安装 Apple Command Line Tools 时执行，并在系统窗口完成安装：

```sh
xcode-select --install
```

### 2. 运行 Python 脚本

```sh
python3 -B MacOS_Patch/python/embedded_compatible.py prepare \
  --source-app 'Navicat Premium.app' \
  --output MacOS_Patch/output/embedded-compatible-rebuild
```

该命令自动完成制作、编译、签名和校验，生成独立 app，不覆盖已安装的应用。输出目录必须不存在、父目录必须存在；重复制作时使用新的输出目录。

### 3. 编译原生库

第 2 步已自动编译，正常制作无需重复执行。仅需单独编译时，在 Finder 中双击 `MacOS_Patch/native/build.command`，或执行：

```sh
MacOS_Patch/native/build.command
```

默认输出为 `MacOS_Patch/output/native-build/NavicatKeychainBridge.dylib`。已有输出时需改用新的输出目录。单独编译不会生成完整 app。

### 4. 安装成品到应用程序目录

正常退出所有 Navicat 实例，在项目根目录执行。以下命令先确认成品主程序存在且可执行，再删除目标同名 app 并复制完整成品，不合并旧文件；`sudo` 会要求输入管理员密码：

```sh
test -x 'MacOS_Patch/output/embedded-compatible-rebuild/Navicat Premium.app/Contents/MacOS/Navicat Premium' && \
sudo /bin/rm -rf '/Applications/Navicat Premium.app' && \
sudo /usr/bin/ditto --noqtn 'MacOS_Patch/output/embedded-compatible-rebuild/Navicat Premium.app' '/Applications/Navicat Premium.app'
```

该操作只替换 app，不清理用户连接配置或钥匙串。复制失败时需重新执行安装，或使用官方安装包恢复。

### 5. 对已安装的 app 签名并校验

保持 Navicat 退出，对 `/Applications/Navicat Premium.app` 执行：

```sh
xattr -cr '/Applications/Navicat Premium.app' && codesign -fs - '/Applications/Navicat Premium.app' && \
codesign --verify --deep --strict '/Applications/Navicat Premium.app'
```

仅对已安装的成品执行，不要对作为脚本输入的官方原版重签名。校验通过不等于厂商公证。

### 6. 启动与使用

第 5 步校验通过后，在 Finder 的“应用程序”目录双击已安装的 app，或执行：

```sh
open '/Applications/Navicat Premium.app'
```

日常启动不需要 Python 或额外启动器。

- 不要同时运行多个副本；首次钥匙串授权提示由用户自行确认。
- 用自造密码测试保存，退出并重新打开同一 app，检查能否读回。
- 出错时记录完整错误信息；不要删除或重置钥匙串。
- 旧密码不会自动迁移，不支持 iCloud 同步和跨应用密码共享。
- 恢复官方版时，退出应用并使用官方安装包覆盖。
- 本地功能修改不等同于有效许可证或账户授权，也不代表所有功能均已验证。
