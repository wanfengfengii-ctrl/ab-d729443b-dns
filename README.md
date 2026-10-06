# DNS IXFR 离线回放服务

权威 DNS 运维平台的增量区日志（IXFR）离线回放器：在应用到生产前，于隔离环境重放
有序变更事务，验证序列号推进、删除命中、新增去重、TTL 一致性、CNAME 排他性与
SOA 唯一性，避免序列回绕、半笔变更或别名冲突产生不可发布的区域快照。

成功时返回最终序列号、规范排序的记录列表与 SHA-256 摘要；任一规则违例则整体
失败，返回定位到笔次与规则的稳定错误码，**绝不暴露部分更新快照**。

## 快速开始

```bash
# 启动 API（宿主机端口可通过 HOST_PORT 配置，默认 8080）
docker compose up -d api
HOST_PORT=9000 docker compose up -d api

# 一次性验证：代码测试 + 构建检查 + 含序列回绕的 API 冒烟，退出码即结论
docker compose run --rm verify ; echo "exit=$?"
# 或
docker compose up --exit-code-from verify --abort-on-container-exit verify
```

`verify` 服务依赖 `api` 健康检查通过后才启动，依次执行：

1. **构建检查**：全部源码字节编译 + 模块导入；
2. **代码测试**：`tests/` 下的 unittest 套件（43 个用例）；
3. **API 冒烟**：对 `api` 服务发起含 RFC 1982 序列回绕
   （`4294967290 → 4294967295 → 4 → 9`）的合法回放、非法序列、删除未命中、
   CNAME 冲突、畸形 JSON 等用例，并与引擎本地结果交叉比对摘要。

全部通过退出码为 0，任一失败退出码为 1。

本地无 Docker 时亦可运行：

```bash
PYTHONPATH=app PORT=8080 python3 -m dnsreplay.server &
PYTHONPATH=app API_URL=http://127.0.0.1:8080 TESTS_DIR=$PWD/tests \
  python3 -m dnsreplay.verify
```

## API

### `GET /healthz`

健康检查，返回 `{"status": "ok", "version": "..."}`。

### `POST /api/dns/ixfr/replay`

请求体：

```json
{
  "zone": "Example.COM.",
  "initial": {
    "soa": {"name": "example.com", "type": "SOA", "ttl": 3600,
            "rdata": {"mname": "ns1.example.com",
                      "rname": "hostmaster.example.com",
                      "serial": 4294967290, "refresh": 7200, "retry": 3600,
                      "expire": 1209600, "minimum": 300}},
    "records": [
      {"name": "www.example.com", "type": "A", "ttl": 300, "rdata": "192.0.2.1"},
      {"name": "mail.example.com", "type": "CNAME", "ttl": 600,
       "rdata": "www.example.com"}
    ]
  },
  "transactions": [
    {"begin_soa": {"...": "serial 4294967290 的完整 SOA"},
     "deletes": [],
     "adds": [{"name": "example.com", "type": "TXT", "ttl": 300,
               "rdata": "v=spf1 -all"}],
     "end_soa": {"...": "serial 4294967295 的完整 SOA"}},
    {"begin_soa": {"...": "serial 4294967295"},
     "deletes": [{"name": "www.example.com", "type": "A", "ttl": 300,
                  "rdata": "192.0.2.1"}],
     "adds": [{"name": "www.example.com", "type": "A", "ttl": 300,
               "rdata": "192.0.2.9"}],
     "end_soa": {"...": "serial 4（回绕）"}}
  ]
}
```

约束：

- `transactions` 为 1–64 笔，按顺序应用；记录总数
  （`initial.records` + 各笔 `deletes` + 各笔 `adds`）不超过 5000；
- 每笔 `begin_soa` 必须与当前 SOA 完全一致，`end_soa` 成为新的当前 SOA；
- 新序列号按 RFC 1982 三十二位串行数规则严格前进（支持回绕，差值须落在
  `(0, 2^31)` 区间），且在整个回放中唯一；
- 仅支持 `A`、`AAAA`、`CNAME`、`TXT`、`SOA`；SOA 只能由事务框架携带，
  不得出现在 `records`/`deletes`/`adds` 中，区域顶点始终恰好一条 SOA；
- 所有记录的属主名必须位于区域内。

成功响应（HTTP 200）：

```json
{
  "ok": true,
  "zone": "example.com",
  "final_serial": 4,
  "record_count": 3,
  "records": [
    {"name": "example.com", "type": "SOA", "ttl": 3600, "rdata": {"...": "..."}},
    {"name": "example.com", "type": "TXT", "ttl": 300, "rdata": "v=spf1 -all"},
    {"name": "www.example.com", "type": "A", "ttl": 300, "rdata": "192.0.2.9"}
  ],
  "sha256": "<64 hex>"
}
```

`records` 按 RFC 4034 规范顺序稳定排序（属主名自右向左按标签比较，再按类型
代码、再按 rdata 规范文本）；`sha256` 为排序后规范文本行
`name ttl type rdata\n` 串联的 SHA-256。

失败响应（HTTP 400，无 `records`/`sha256` 字段）：

```json
{
  "ok": false,
  "error": {
    "code": "E_SERIAL_NOT_ADVANCING",
    "rule": "SERIAL_ADVANCE",
    "message": "transaction 1 serial 5 does not strictly advance past 10 (RFC 1982)",
    "transaction": 1,
    "detail": {"current_serial": 10, "new_serial": 5}
  }
}
```

`transaction` 为失败笔次的 0 基下标；信封或初始状态错误时为 `null`。

### 稳定错误码

| code | rule | 含义 |
|---|---|---|
| `E_SCHEMA` | `SCHEMA` | 请求结构非法（缺键、类型错误、非 JSON） |
| `E_TXN_COUNT` | `TXN_COUNT` | 事务数不在 1–64 |
| `E_RECORD_LIMIT` | `RECORD_LIMIT` | 记录总数超过 5000 |
| `E_NAME_INVALID` | `NAME_CANONICAL` | 非法 DNS 名 |
| `E_NAME_OUT_OF_ZONE` | `ZONE_ALIGNMENT` | 属主名在区域之外 |
| `E_TYPE_UNSUPPORTED` | `TYPE_SUPPORT` | 记录类型不受支持 |
| `E_TTL_INVALID` | `TTL_RANGE` | TTL 超出 `[0, 2^31-1]` |
| `E_RDATA_INVALID` | `RDATA_SYNTAX` | rdata 语法非法（如非法 IP） |
| `E_RRSET_TTL_MISMATCH` | `RRSET_TTL` | 同一记录集 TTL 不一致 |
| `E_CNAME_CONFLICT` | `CNAME_EXCLUSIVE` | CNAME 与同名其他数据共存（含多 CNAME） |
| `E_SOA_CARDINALITY` | `SOA_CARDINALITY` | SOA 不在顶点、出现在增删集合中或缺失 |
| `E_SOA_BEGIN_MISMATCH` | `SOA_BEGIN` | 事务未以当前 SOA 开始 |
| `E_SOA_END_UNIQUE` | `SOA_END_UNIQUE` | 新序列号在回放中不唯一 |
| `E_SERIAL_NOT_ADVANCING` | `SERIAL_ADVANCE` | 新序列号未按 RFC 1982 严格前进 |
| `E_DELETE_NOT_FOUND` | `DELETE_EXISTING` | 删除未命中现存记录 |
| `E_ADD_DUPLICATE` | `ADD_UNIQUE` | 新增与现存记录重复 |

## 规范化规则

- 名称：去除一个末尾根点、逐标签小写化（DNS 大小写不敏感）；标签允许
  字母、数字、连字符与下划线（兼容 `_dmarc` 等），长度 1–63，全名 ≤ 253；
- 类型：大小写不敏感，统一大写输出；
- `A`/`AAAA`：解析后以规范文本输出（IPv6 压缩小写）；
- `CNAME`/SOA 的 `mname`、`rname`：按名称规则规范化；
- `TXT`：不透明字符串，大小写保留；摘要中以 JSON 引号形式消除歧义。

## 目录结构

```
Dockerfile              API 镜像（含 HEALTHCHECK，非 root 运行）
docker-compose.yml      api 服务（健康检查、可配宿主机端口）+ 一次性 verify 服务
app/dnsreplay/engine.py 回放引擎：全部校验规则与规范输出
app/dnsreplay/server.py 纯标准库 HTTP 服务（无第三方依赖）
app/dnsreplay/verify.py 一次性验证入口（python -m dnsreplay.verify）
tests/test_engine.py    43 个单元测试
```
