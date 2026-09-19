# CIDR 策略规范化 API

基于 **Python + FastAPI + 标准库 `ipaddress`** 的 CIDR 策略规范化服务。

接收 `allow`（允许）与 `deny`（拒绝）两个 CIDR 列表，分别对 **IPv4** 与 **IPv6**
计算集合差 **`allow − deny`**，返回与之**等价、互不重叠、数量最少**的 CIDR 集合。

## 算法语义

- **分族处理**：IPv4、IPv6 互不影响，分别计算。
- **递归拆分**：当某个 deny 前缀“切穿”allow 网段时（deny 是 allow 的严格子网），
  沿前缀树把 allow 反复二分为左右子网，直到每个片段要么完全落在 deny 内（丢弃），
  要么完全在 deny 外（保留）。
- **仅合并完整兄弟前缀**：只有当两个前缀长度相同、地址相邻，且恰好拼成同一父网段
  （即父网段的两个完整“兄弟”）时，才合并为父前缀。相邻但**不**构成完整兄弟的网段
  保持独立（例如 `10.0.0.0/25` 与 `10.0.0.192/26` 不会合并）。合并会迭代进行，
  直到无法再合并，从而保证数量最少。
- **稳定排序**：结果先按地址族（IPv4 在前、IPv6 在后），族内按
  **网络地址**升序、再按**前缀长度**升序排列。
- **去重与统计**：对 allow 统计输入原始条数、去重后条数、最终输出条数。
  带主机位的写法（如 `10.0.0.5/24`）会被规范化为网络地址（`10.0.0.0/24`），
  因此与 `10.0.0.0/24` 视为重复。
- **非法输入**：任何无法解析的 CIDR（如 `not-a-cidr`、`10.0.0.0/33`、
  `999.0.0.0/8`）一律返回 **HTTP 422**，并在响应中给出出错所在列表的下标与原值。

## 快速开始（单条命令）

无需手动安装依赖，Docker 会在构建/启动时自动安装。在仓库根目录执行：

```bash
docker compose up --build -d
```

服务监听宿主机的 **8000 端口**。健康检查：

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

交互式 API 文档（Swagger UI）：<http://localhost:8000/docs>

停止服务：

```bash
docker compose down
```

> 不使用 Docker 时，也可本地运行（依赖需提前安装）：
>
> ```bash
> pip install -r requirements.txt
> uvicorn app.main:app --host 0.0.0.0 --port 8000
> ```

## 接口

### `POST /normalize`

请求体（两个字段均可省略，默认为空数组）：

| 字段    | 类型       | 说明                        |
| ------- | ---------- | --------------------------- |
| `allow` | `string[]` | 允许的 CIDR 前缀列表        |
| `deny`  | `string[]` | 拒绝的 CIDR 前缀列表（从 allow 中挖除） |

响应：

- `ipv4.networks` / `ipv6.networks`：规范化后的最小 CIDR 字符串数组。
- `counts.ipv4` / `counts.ipv6`：
  - `input`：该族 allow 的原始输入条数（含重复）。
  - `unique`：去重后的条数（主机位规范化后相同的视为同一条）。
  - `output`：最终输出的 CIDR 条数。

#### 示例

```bash
curl -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{
        "allow": ["10.0.0.0/22", "10.0.0.5/24", "2001:db8::/32"],
        "deny":  ["10.0.0.0/24", "2001:db8::/33"]
      }'
```

```json
{
  "ipv4": { "networks": ["10.0.1.0/24", "10.0.2.0/23"] },
  "ipv6": { "networks": ["2001:db8:8000::/33"] },
  "counts": {
    "ipv4": { "input": 2, "unique": 1, "output": 2 },
    "ipv6": { "input": 1, "unique": 1, "output": 1 }
  }
}
```

说明：`10.0.0.0/22` 被 `10.0.0.0/24` 递归切开——
`/22 = 10.0.0.0/23 + 10.0.2.0/23`，前者又被 `/24` 切成
`10.0.0.0/24`（被 deny）与 `10.0.1.0/24`（保留）；
`10.0.0.5/24` 规范化为 `10.0.0.0/24`，与 `/22` 重叠，故去重后唯一值为 1。

#### 非法 CIDR（422）

```bash
curl -i -X POST http://localhost:8000/normalize \
  -H 'Content-Type: application/json' \
  -d '{"allow": ["bogus/99"]}'
```

```json
{
  "detail": [
    {
      "type": "invalid_cidr",
      "msg": "'bogus/99' does not appear to be an IPv4 or IPv6 network",
      "index": 0,
      "value": "bogus/99"
    }
  ]
}
```

### `GET /health`

返回 `{"status":"ok"}`，用于容器/负载均衡健康检查。

## 必要配置（端口）

- 服务在容器内监听 `8000`，Compose 默认映射宿主机 `8000:8000`。
- 如需改用其他宿主机端口，修改 `docker-compose.yml` 的 `ports`，例如
  `"9000:8000"`（左侧为宿主机端口，右侧容器端口保持 `8000`）。
- 无数据库、无外部服务、无必需环境变量；依赖在镜像构建时随启动安装完成。

## 项目结构

```
app/
  __init__.py
  cidr.py       # 核心算法（仅依赖标准库 ipaddress）：解析、递归拆分、兄弟合并、统计
  schemas.py    # Pydantic 请求/响应模型
  main.py       # FastAPI 应用：POST /normalize、GET /health
Dockerfile
docker-compose.yml
requirements.txt
requirements-dev.txt   # 测试用：pytest、httpx
test_core.py    # 核心算法的差分/性质测试（4000 组随机用例 + 手工用例）
test_api.py     # HTTP 层测试（TestClient）
```

## 运行测试

```bash
pip install -r requirements-dev.txt
pytest -q
python3 test_core.py
```

`test_core.py` 在一个小规模 IPv4 地址空间（`10.0.0.0/24`）上，用“逐地址覆盖”
作为正确性基准，对 4000 组随机 allow/deny 输入校验结果**等价、互不重叠、
无残留可合并兄弟（数量最少）、排序正确**。
