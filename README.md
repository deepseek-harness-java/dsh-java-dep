# DSH Dependency Radar（依赖雷达）

> DSH Java Native Plugin 独立 AI 产品 #6：解析 Maven/Gradle 依赖树、找版本冲突、过期检查、CVE 关键词提示、升级路径建议。**只分析，不执行升级、不联网拉包。**

## 概览

- **端口**：8097
- **模块**：`dsh-java-dep-app`（Spring Boot）+ `dsh-java-dep-plugin`（Java Native 插件）
- **插件 ID**：`dsh-java-dep`，入口类 `cn.xiaofuge.dsh.dep.plugin.DshDependencyRadarPlugin`
- **工具前缀**：`dep_`（暴露为 `plugin__dsh-java-dep__<tool>`）

## AI 工具（5 个）

| 工具 | 说明 |
|---|---|
| `dep_parse_tree(text, format?)` | 解析 mvn dependency:tree / gradle dependencies 文本为结构化节点（含深度） |
| `dep_find_conflicts(text, format?)` | 同坐标多版本冲突检测 + 统一版本建议 |
| `dep_outdated(deps, latest?)` | 过期依赖对比（内置最新版本样例表，可传 latest 覆盖） |
| `dep_cve_scan(deps)` | CVE 关键词提示（本地启发式表：jackson-databind/logback/netty/fastjson 等低版本高危组件） |
| `dep_upgrade_path(deps, target?)` | 升级顺序建议：底层→框架→应用库，含风险级别与回归检查项 |

解析器兼容三种 Maven omitted 形态：坐标被括号包裹 `(ga:art:jar:ver - omitted for conflict)`、尾注 `(x - omitted ...)`、纯尾注 `- omitted ...`；同时支持 Gradle `+---` 输出。deps 参数兼容对象数组 / JSON 字符串 / 逐行 `group:artifact:version` 文本。

## REST API（8097）

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/dep/parse` | `{text, format}` → nodes[] |
| POST | `/api/dep/conflicts` | `{text, format}` → conflicts[] |
| POST | `/api/dep/outdated` | `{deps[], latest?}` → items[] |
| POST | `/api/dep/cve-scan` | `{deps[]}` → hits[]（含 disclaimer） |
| POST | `/api/dep/upgrade-path` | `{deps[], target?}` → steps[] |
| POST | `/api/assistant/stream` | SSE：`{agentId, message}` → 转发 harness |

## 运行

```bash
mvn package -DskipTests
SERVER__PORT= java -jar dsh-java-dep-app/target/dsh-java-dep-app-0.1.0-SNAPSHOT.jar --server.port=8097

cp dsh-java-dep-plugin/target/dsh-java-dep-plugin-0.1.0-SNAPSHOT.jar ~/.dsh/standalone/plugins/dsh-java-dep-plugin.jar
curl -X POST http://127.0.0.1:8090/api/harness/plugins/install -H 'Content-Type: application/json' -d '{
  "pluginId":"dsh-java-dep","jarName":"dsh-java-dep-plugin.jar",
  "displayName":"DependencyRadar 依赖雷达","pluginVersion":"0.1.0","runtimeType":"JAVA_NATIVE",
  "sourcePath":"'"$HOME"'/.dsh/standalone/plugins/dsh-java-dep-plugin.jar",
  "entrypoint":"cn.xiaofuge.dsh.dep.plugin.DshDependencyRadarPlugin","installMode":"REPLACE"}'
curl -X POST http://127.0.0.1:8090/api/harness/plugins/activate -H 'Content-Type: application/json' -d '{"pluginId":"dsh-java-dep"}'
```

## E2E

```bash
python3 dep_radar_e2e.py   # 8/8 PASS
```

覆盖：树解析（T0）、冲突检测（T1）、过期检查（T2）、CVE 提示含免责声明（T3）、升级路径（T4）、空依赖 400（T5）、**AI 对话真实调用 dep_find_conflicts/dep_cve_scan（T6）**、**AI 安全红线：用户要求直接执行 mvn 升级时拒绝执行、改为建议人工步骤（T7）**。

## 安全红线

- **不执行升级**：全部工具只读；AI 被要求"直接跑 mvn 升级"时必须拒绝，只能给出人工操作步骤与升级顺序清单。
- **不联网拉包**：过期检查与 CVE 扫描都基于本地内置表，无任何网络请求。
- CVE 结论一律注明"本地启发式提示，以官方 CVE 数据库（NVD / GitHub Advisory）通告为准"，禁止断言一定存在漏洞。

## 截图

- `screenshots/01-home.png` — 雷达工作台（依赖树 / 体检）
- `screenshots/02-ai-drawer.png` — AI 调用工具输出 CVE 提示表 + 免责声明 + 升级建议
- `screenshots/03-safety.png` — 安全红线：拒绝直接执行 mvn 升级，给出人工操作方式
