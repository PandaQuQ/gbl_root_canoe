# TB323FU STRB V5 — CFG 可达调用与副作用审计

本文档与相关工具位于仓库的 `submodules/patcher/`。
**这是离线工程验证包扩展，不是经过实机验证的假回锁版本。** 不会刷写任何设备分区，也不会把候选 STRB 判定自动升格为安全放行。

**约定**：下文命令均以 `submodules/patcher/` 为当前工作目录（先 `cd submodules/patcher`）。

## 相对 V3 的变化

- **C 补丁器源码未改**：`src/patchs/core.c`、`src/arm64_inst/utils.c` 与失败关闭 V3 完全一致。
- **新增** `tools/call_effects.py`：分析 `LinuxLoader.efi` 中从状态溢出写入 `0x17E30` 到状态恢复 `0x191F0` 的控制流，以及区间内可达调用点的保守副作用摘要。
- **新增测试**：`tests/test_call_effects.py`、`tests/test_v4_guardrails.py`。

## 运行

需要 `llvm-objdump` 在 PATH 中。工具只读取镜像，不写入设备，也不生成修改后的 EFI。

```powershell
cd submodules\patcher
py -3 .\tools\call_effects.py "C:\path\to\LinuxLoader_b.efi" --out .\reports\call_effects_b.json
```

```bash
cd submodules/patcher
python3 tools/call_effects.py /path/LinuxLoader_b.efi --out reports/call_effects_b.json
python3 -m unittest discover -s tests -v
```

诊断 JSON（`call_effects_*.json`）体积较大，默认只放在本地 `reports/`，不提交进仓库。

## 结果及限制

- A/B 各有 **126** 个处在 CFG 起点到终点可达路径交集中的调用位置。
- 分支条件未使用约束求解；**CFG 可达不等于真实执行可达**。
- `bl` 的被调函数会被独立审计，但当前**不做跨函数别名安全证明**。被调函数中的 `sp` 属于被调函数自己的栈帧，不能直接等同于调用者的 `SP+0x20`。
- 被调函数有其他调用、指针存储或间接控制流时，都不宣称无副作用。
- 任何结果均 **不授权刷入或回锁**，**未提供新的可刷写 boot.efi**。

## 尚未完成

精确的路径条件求解、指针逃逸、跨函数 mod/ref 摘要、调用约定及栈帧别名验证、自动补丁器集成、Windows 构建验证与真机验证。不能声称整套假回锁已经完成。
