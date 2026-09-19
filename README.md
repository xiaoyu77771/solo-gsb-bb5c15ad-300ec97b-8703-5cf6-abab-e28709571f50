# CIDR Policy Normalizer

基于 **Python + FastAPI + 标准库 `ipaddress`** 的 CIDR 策略规范化 API。

接收 `allow` 与 `deny` 两个 CIDR 列表，分别对 **IPv4 / IPv6** 计算集合差
**allow − deny**，返回与原策略**等价、互不重叠且数量最少**的 CIDR 集合。

- deny 前缀切穿 allow 网段时，按二叉前缀树**递归对半拆分**直到边界对齐；
- 仅当两个网段构成**完整相邻的兄弟前缀**（同一父网的左右两半）时才合并，
  借助 `ipaddress.collapse_addresses` 实现，保证最小化且不会跨边界聚合；
- 输出按 **地址族（IPv4 → IPv6）→ 网络地址 → 前缀长度** 稳定排序；
- 统计 allow / deny 的输入数量、去重后数量（按族拆分）与最终输出数量；
- 非法 CIDR（格式错误、越界前缀、主机位非零）统一返回 **HTTP 422**。

## 一条命令启动

依赖在镜像构建时安装完成，容器启动即提供服务：

```bash
docker compose up -d --build
```

服务监听宿主机 **8000** 端口（容器内固定 8000）。

健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

交互式文档：<http://localhost:8000/docs>

## 配置

无需任何必填配置。唯一可选项是宿主机映射端口（容器内始终为 8000）：

```bash
HOST_PORT=9000 docker compose up -d --build   # 宿主机改用 9000
```

默认端口：**8000**（见 `docker-compose.yml` 的 `${HOST_PORT:-8000}:8000`）。

## API

### `POST /normalize`

请求体：

| 字段   | 类型       | 说明                                   |
| ------ | ---------- | -------------------------------------- |
| `allow` | `string[]` | 允许列表，IPv4/IPv6 可混填，可省略（默认 `[]`） |
| `deny`  | `string[]` | 拒绝列表，规则同上                     |

CIDR 规则：

- 标准 CIDR：`10.0.0.0/24`、`2001:db8::/32`；
- 裸地址按主机前缀处理：`10.0.0.1` ≡ `10.0.0.1/32`，`::1` ≡ `::1/128`；
- 主机位非零（如 `10.0.0.1/24`）视为非法，返回 422。

示例：

```bash
curl -s -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/24", "10.0.0.0/24", "2001:db8::/32"],
        "deny":  ["10.0.0.128/25", "2001:db8:1::/48"]
      }'
```

响应：

```json
{
  "ipv4": ["10.0.0.0/25"],
  "ipv6": ["2001:db8::/48", "2001:db8:2::/47", "... 共 16 段 ..."],
  "stats": {
    "allow": {"input": 3, "unique": 2, "duplicates_removed": 1, "ipv4": 1, "ipv6": 1},
    "deny":  {"input": 2, "unique": 2, "duplicates_removed": 0, "ipv4": 1, "ipv6": 1},
    "output": {"ipv4": 1, "ipv6": 16, "total": 17}
  }
}
```

字段说明：

- `ipv4` / `ipv6`：allow − deny 的最小 CIDR 列表，按网络地址、前缀长度排序；
- `stats.allow` / `stats.deny`：
  - `input`：请求中的原始条目数；
  - `unique`：去重后的网络数；
  - `duplicates_removed`：被去掉的重复条目数；
  - `ipv4` / `ipv6`：去重后各地址族的网络数；
- `stats.output`：最终输出的 IPv4 / IPv6 及总网段数。

非法输入返回 422：

```bash
curl -i -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{"allow": ["10.0.0.1/24"], "deny": []}'
# HTTP/1.1 422 Unprocessable Entity
# {"detail":[{"type":"value_error","loc":["body","allow"],
#   "msg":"Value error, 10.0.0.1/24 has host bits set", ...}]}
```

## 算法说明

1. **解析校验**：`ipaddress.ip_network(value, strict=True)` 严格解析；
2. **族拆分 + 输入折叠**：IPv4、IPv6 独立处理，先对 allow / deny 各自
   `collapse_addresses` 去重、去重叠、去包含；
3. **递归差集**（`app/policy.py::_diff`）：对每个 allow 网络：
   - deny 等于或包含该网络 → 整个删除；
   - deny 与其不相交 → 整段保留；
   - deny 是其严格子网（切穿）→ 拆成左右两个兄弟半区递归处理，
     被整段拒绝的半区丢弃，未触及的半区整体保留；
4. **兄弟合并**：结果再次 `collapse_addresses`，只有完整相邻兄弟前缀
   才能合并回父前缀，从而保证等价性、互不重叠与最少数量；
5. **稳定排序**：按地址族、`network_address.packed`、前缀长度排序。

## 本地开发（不使用 Docker）

需要 Python 3.11+：

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

运行测试（仅核心测试依赖标准库；API 测试需安装 fastapi、httpx、pytest）：

```bash
pip install -r requirements.txt pytest httpx
pytest -q
```

测试包含与 `ipaddress.address_exclude` 参考实现对拍的 IPv4/IPv6 随机性质
用例，验证结果的等价性与最小性。

## 项目结构

```
.
├── app/
│   ├── main.py        # FastAPI 应用：GET /health、POST /normalize
│   ├── policy.py      # 解析、递归拆分、兄弟合并、统计（仅 ipaddress）
│   └── schemas.py     # Pydantic 请求/响应模型与 422 校验
├── tests/
│   ├── test_policy.py # 核心算法单测 + 随机对拍（111 例）
│   └── test_api.py    # API 层测试（422、统计、空请求等）
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```
