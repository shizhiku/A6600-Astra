# 71 · libsencore 报文格式线索（副控制器文件传输）

本轮为离线字符串分析。无设备写入。

## 一、关键字符串与其含义

| 字符串 | 含义推断 |
|---|---|
| `Receive Pkt Err : resCode=0x%x, Adrs=0x%x, DataSize=0x%x` | 应答包字段：结果码、地址、数据长度 |
| `Receive Pkt Err : reqSize=0x%x, resSize=0x%x (Offset=%d > 300Byte)` | 分片窗口 0x300（768）字节 |
| `[cpyMemUnit] ... ( Offset=%d > 300Byte )` | 同上，带偏移的分片拷贝 |
| `Error - Trans(to Subsystem) size 0x%X is larger than total extent size 0x%X` | 发送侧有 extent 总长校验 |
| `Error - Trans(to Subsystem) size 0x%X is larger than Receive size 0x%X` | 与接收缓冲长度比对 |
| `NortifyAdrsErr-TransType 0x%02X` | 传输类型字段（8 位） |
| `ProcessEndErr - Invalid TransType - 0x%02X` | 同上，类型非法时告警 |
| `CommandErr : LSI sync : FIN_SEND_DATA` | 命令名：`FIN_SEND_DATA`（发送结束） |
| `Receive Packet Err ( DataSize = 0x%x )` | 长度校验 |
| `resDataAddress==NULL` | 应答数据地址为空 |
| `mmap Failed ( ADRS=0x%08X, SIZE=%u )` | 共享内存映射失败 |

## 二、可推断的协议轮廓

1. 主控与副控制器（LSI / sub-micro）通过 **osal 消息 + 共享内存**通信；
2. 传输以**地址 + 长度**描述（`Adrs`/`DataSize`），单次窗口上限 **0x300 字节**，超出按偏移分片；
3. 有**传输类型**字段（`TransType`），包含 `FIN_SEND_DATA` 之类的命令；
4. 应答带 `resCode`，错误时有明确错误码；
5. 文件（字体）通过该通道取回后写入 `/tmp/images/`。

## 三、这是当前唯一的根本性阻塞

前面已确认：

- 中文字体不在固件内（`/usr` 只有 3 个 `.ltt`）；
- 相机 `/tmp/images/` 中有中文 `.ltt`（已采集 1.96 MB）；
- 字体注册由**一次性初始化**完成，不含中文；
- 中文必须走“副控制器传输 → `/tmp/images` → 注册”这条路径；
- 仅把文件放进 `/tmp/images` **不触发注册**。

**因此：不实现该通道的文件传输，UI 无法越过字体加载。**

## 四、实现该通道所需工作（估计）

1. 逆向 `libsencore` 的消息结构体（字段偏移、命令码表、`TransType` 取值）；
2. 确认该通道在 QEMU 中对应的硬件路径（SIO 通道号、FIFO 窗、中断）；
3. 在 QEMU 侧按请求返回 `/tmp` 中的文件内容（分片 0x300）；
4. 验证注册被触发、`TextRM_loadFont` 命中。

工作量显著，且需要逐步试错；这不是本轮剩余轮次能完成的。

## 五、证据

- `02-脚本/inspect_sencore_packets.py`
- `03-证据/静态分析/libsencore.so`（349,760 B）

## 六、状态

原厂 UI 未启动；ASTRA UI 未验证；实验固件不可刷；本轮无设备操作。
