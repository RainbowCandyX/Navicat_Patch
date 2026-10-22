# Navicat_Patch

适用于 **Navicat Premium 17 / 18（x64）** 的 `winmm.dll` 代理补丁。

## 功能

- 转发系统 WinMM 导出，保留原有接口。
- 通过特征码定位，在内存中修改试用时间检查和版本状态。
- 成功时不弹窗，仅在失败时使用 `MessageBoxW` 提示。
- 不修改磁盘上的 EXE 和 DLL；特征或原始字节不匹配时不应用补丁。

## 使用

1. 使用 Visual Studio 打开工程，选择 `Release | x64`，生成 `winmm.dll`。
2. 关闭 Navicat，备份安装目录中已有的同名 DLL。
3. 将生成的 `winmm.dll` 放入 `navicat.exe` 所在目录，然后启动 Navicat。

## 还原

关闭 Navicat，移除部署的补丁 DLL；如果原目录已有 `winmm.dll`，恢复之前的备份。
