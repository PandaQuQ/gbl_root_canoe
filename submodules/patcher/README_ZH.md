# TB323FU / gbl_root_canoe STRB 目标识别与构建安全门 V3

基于用户提供的 `gbl_root_canoe` 源码提交 `e3f935c4db212495c9eac219cee6f6badea65641`。
**这是离线工程验证包，不是经过实机验证的假回锁版本。** 不会刷写任何设备分区，也不会把候选 STRB 判定自动升格为安全放行。

## 本次实现

1. **真实目标自动发现**：读取原始 `LinuxLoader.efi`，从 `LDRB` 状态源出发，用 CFG 路径探索、寄存器和 SP 栈槽污点传播、`STP/LDP` 解析查找下游 `STRB`；不预先指定目标 STRB 偏移。支持已知 SP 相对寄存器别名，并区别已知不重叠与未知别名写入。
2. **函数调用处理**：按 AAPCS64 保留 X19–X28、清除调用者可破坏的 X0–X18；记录已知 SP 指针通过参数传入被调用函数的可能逃逸。未知指针、未知指令、间接调用、栈指针调整会保留为不确定性，不会假定无副作用。
3. **C 补丁器失败关闭**：移除 `LocSet` 为空时“任意 STRB”回退，修正 `SUCCESS=0` 的误判，无法证明 STRB 链时让 `PatchBuffer()` 返回失败且**不输出 EFI**。
4. **一体化构建门**：`tools/safe_build.py` 运行自动发现、生成 JSON、调用 C 补丁器。即使某个补丁器产出文件，也只在临时目录比较，不把它交付为 `boot.efi`。
5. **回归测试**：Python 单元测试和 TB323FU A/B 两个真实样本；Linux GCC 构建，并分别用 AddressSanitizer / UndefinedBehaviorSanitizer 运行真实样本，未观察到 sanitizer 报告（程序按照设计拒绝输出）。

## 本次真实镜像结果

| 检查 | A 槽位 | B 槽位 |
| --- | --- | --- |
| 自动发现的 STRB 候选 | `0x19214` | `0x19214` |
| 候选路径数量（状态模型中的路径，不是独立实机执行路径） | 8 | 8 |
| 搜索预算 | 未耗尽 | 未耗尽 |
| 调用/别名未决 | 是 | 是 |
| C 补丁器返回码 | 1（安全拒绝） | 1（安全拒绝） |
| 输出可刷写 boot.efi | 否 | 否 |

候选链：`0x17B20 LDRB W21` → `0x17E30 STR X21,[SP,#0x20]` → `0x191F0 LDP X11,X10,[SP,#0x20]` → `0x19214 STRB W11,[SP,#0x60]`。

**路径的数量可能随着抽象状态细化发生变化，不意味着候选的物理执行路径数量变化。** 静态候选仍未证明分支条件可满足、所有可能内存别名、间接调用与栈指针逃逸的完整副作用，也未通过实机启动、AVB、SN 的验证。

## Windows 使用

安装 Python 3 和 LLVM（保证 `llvm-objdump.exe` 在 PATH）。编译 C 补丁器另需 MinGW-w64（`x86_64-w64-mingw32-gcc` 在 PATH）。源码包内 `build_windows.bat` 使用 Windows CRLF。

在 PowerShell 中进入解压目录：

```powershell
.\build_windows.bat
py -3 .\tools\safe_build.py "C:\Users\Admin\Desktop\tk\LinuxLoader_a.efi" --patcher .\patcher\patch_abl_safe.exe --out .\reports
py -3 .\tools\safe_build.py "C:\Users\Admin\Desktop\tk\LinuxLoader_b.efi" --patcher .\patcher\patch_abl_safe.exe --out .\reports
py -3 -m unittest discover -s tests -v
```

可单独运行目标自动发现：

```powershell
py -3 .\tools\strb_trace.py "C:\path\to\LinuxLoader_b.efi" --out .\reports\trace_b.json
```

**注意**：Windows 交叉编译脚本已编写，未在本环境的 Windows/MSYS2 下实机编译；这里真正编译并执行验证的是 Linux 版本。构建输出文件名 `patch_abl_safe.exe` 并不表示“假回锁安全认证”。

## Linux 使用

```bash
make -C patcher build
python3 -m unittest discover -s tests -v
python3 tools/safe_build.py /path/LinuxLoader_a.efi --patcher patcher/build/patch_abl --out reports
python3 tools/safe_build.py /path/LinuxLoader_b.efi --patcher patcher/build/patch_abl --out reports
```

如果要运行真实镜像回归，可提供环境变量 `EFI_A`、`EFI_B`、`PATCHER_BIN`，参见 `tests/test_real_images.py`。

## 文件结构

- `patcher/`：从指定提交提取的 C 补丁器完整构建子项目，带失败关闭修复；`build/patch_abl` 是在 Linux 编译的版本。
- `patches/patcher_fail_closed.patch`：针对原始提交的可审查差异补丁。
- `tools/strb_trace.py`：只读 CFG 自动发现/内存别名诊断工具。
- `tools/safe_build.py`：离线分析 + 临时构建安全门；默认永不放行刷写。
- `tests/`：17 个测试（其中 1 个真实镜像集成测试在未提供样本路径时跳过）。
- `reports/`：本次真实设备镜像的离线测试、C 补丁器日志与 JSON 报告。

## 尚未完成／无法从离线材料认定

- 对所有间接内存访问的精确别名分析和跨过程 mod/ref 摘要，特别是堆/全局结构可能携带的栈地址。
- 全部控制流路径条件的可满足性检验、所有寄存器/SIMD 指令语义的完整处理。
- 将“候选目标”升级成足以驱动自动刷写的正式证明。
- Windows 可执行文件的本地编译和运行验证。
- **实机验证生成 EFI 的启动行为、SN 状态、AVB 状态与故障恢复能力。**

目前交付的是**可编译、可测试、可诊断并拒绝不安全输出的 V3 工程单元**，不是“整个假回锁方案已安全完成”。请勿将旧的 `boot.efi` 视为已验证，亦不要因为日志显示成功就真正锁定 Bootloader。
