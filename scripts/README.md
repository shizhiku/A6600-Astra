# 脚本目录

609 个文件，全部为本项目自写。**按数字前缀对应研究轮次**，不是按功能分层的历史遗留堆放。

> ⚠️ 这些脚本绑定作者环境（路径已脱敏为 `<WORKSPACE>` 等占位符），**不能直接运行**。
> 它们是方法的载体，不是开箱即用的工具。**更不要指向你的相机。**

## 一、命名约定

| 形态 | 含义 |
|---|---|
| `NN_xxx.py` / `NN_xxx.sh` | 第 `NN` 轮的实验脚本 |
| `136_xxx.py` | 第 136 轮（最新） |
| `a6600_xxx.py` | 固件容器通用工具（解包/解码） |
| `patch_xxx.py` | 生成二进制补丁或修改镜像 |
| `find_xxx.py` / `scan_xxx.py` | 静态检索 |
| `resolve_xxx.py` | 解析地址/符号/调用链 |
| `disasm_xxx.py` | 反汇编辅助 |
| `98_pmca_xxx` | 相机服务模式（只读）驱动工具 |
| `check_xxx.py` | 校验与体检 |

## 二、目录结构

```
scripts/
├── check_repo_hygiene.py   # 仓库卫生检查（CI 使用）
├── INDEX.md                # 全部文件清单（自动生成）
├── (数字前缀).py / .sh      # 各轮实验脚本（扁平，609 中的大部分）
├── tools/                  # 早期工具
│   ├── port/               # 镜像构建与移植
│   ├── preload/            # 早期注入探针
│   └── probe/              # 只读探针与部署
├── preload/                # LD_PRELOAD 注入/探针的 C 源码
└── menu-92/                # 原厂菜单专题的脚本与源码
```

## 三、常用入口（如果只想看几个）

| 目的 | 脚本 |
|---|---|
| 固件容器解包/重打包 | `tools/repack_a6600.py`、`tools/decrypt_*.py`、`tools/port/build_full_image.py` |
| 镜像内文件系统操作 | `tools/read_usr.py`、`tools/port/patch_a6600_usr.py` |
| 按键映射分析 | `92_menu_map.py`、`92_infra_key_map_scan*.py` |
| QEMU 启动与注入 | `qemu_boot_trial.sh`、`tools/port/patch_image.sh`、`98_patch_qemu_*.py` |
| 相机只读采集 | `98_pmca_pull.py`、`98_pmca_shell_connect.py`、`98_cam_readonly.py` |
| 五代 UI 桥接 | `tools/port/build_shim.py`、`preload/97_astra_bridge*.c` |
| 崩溃/栈分析 | `preload/98_crash_trace_preload.c`、`98_analyze_*.py` |
| 仓库卫生 | `check_repo_hygiene.py` |

## 四、依赖

- **Python 3**：`pyelftools`、`capstone`、`pycryptodomex`（`Cryptodome`）
- **WSL / Linux**：部分脚本用 `/mnt/c/...` 路径，需在 WSL 中运行
- **交叉工具链**：部分 C 源码为 ARM 目标（`arm-linux-gnueabi-*`）
- **QEMU**：自建 `sony-a6400` machine

缺少依赖时脚本会直接报错，这是预期行为——请按报错自行安装。

## 五、安全提醒

- `98_pmca_*` / `98_cam_*` 是**只读**工具，但**不要**在你不拥有的设备上运行
- 任何 `patch_*` / `repack_*` 产出的镜像都**不可刷入**（分区 CRC 清单未同步）
- 密钥占位符见 [../docs/SANITIZATION.md](../docs/SANITIZATION.md)

## 六、贡献

新增脚本请遵循 [../CONTRIBUTING.md](../CONTRIBUTING.md)：
可独立运行、路径参数化、不提交二进制、不提交 `__pycache__`。
