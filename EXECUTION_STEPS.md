# RSplitCap 执行步骤

## 第一阶段：pcap → .rsplit 归档

### 批量为 pcap 文件创建归档

```bash
cargo build --release

for f in ./dataset/*.pcap ./dataset/*.pcapng; do
  name=$(basename "$f" | sed 's/\.[^.]*$//')
  ./target/release/rsplitcap --mode archive -r "$f" --archive "./archives/$name.rsplit" -s session
done
```

### 验证归档

```bash
./target/release/rsplitcap --mode extract --archive data.rsplit --list-flows
```

---

## 第二阶段：处理流

### 方式 A：Python 原生库（推荐）

```bash
pip install rsplitcap
```

```python
import rsplitcap

# 直接读取 pcap
archive = rsplitcap.read_flows("capture.pcap", strategy="session")

# 或从归档读取
archive = rsplitcap.Archive.open("data.rsplit")

for flow in archive.flows():
    for pkt in flow.packets():
        process(pkt.data, pkt.ts)

# 创建归档
rsplitcap.create_archive("input.pcap", "output.rsplit")

# 管道模式
for pcap in rsplitcap.pipe_archive("data.rsplit"):
    process(pcap)  # pcap 是完整标准 pcap，scapy 直接解析
```

### 方式 B：CLI 管道

```bash
rsplitcap --mode extract --archive data.rsplit --pipe | python process.py
```

管道格式：`[8B 长度 (u64 LE)][完整标准 pcap]...`

Python 端：
```python
import struct, sys

while True:
    raw = sys.stdin.buffer.read(8)
    if not raw: break
    length = struct.unpack("<Q", raw)[0]
    pcap = sys.stdin.buffer.read(length)
    process(pcap)
```

### 方式 C：CLI 批量文件

```bash
rsplitcap --mode extract --archive data.rsplit --filter-proto tcp -o ./tcp_flows/
```

---

## 设计说明

- rsplitcap 只负责快速分割流，输出始终是标准 pcap 格式
- 下游程序只看到"已分割好的 pcap 文件"，不需要任何自定义解析
- 长度前缀是通用流式分帧方式（管道不支持 seek/peek），每流数据 100% 标准 pcap
