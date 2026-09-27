package cn.xiaofuge.dsh.dep.plugin;

import cn.xiaofuge.deepseek.harness.domain.model.entity.AbstractTool;
import cn.xiaofuge.deepseek.harness.domain.model.entity.ToolDefinition;
import cn.xiaofuge.deepseek.harness.domain.spi.AbstractHarnessPlugin;
import cn.xiaofuge.deepseek.harness.domain.spi.PluginContext;
import cn.xiaofuge.deepseek.harness.domain.spi.PluginHookResult;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

public class DshDependencyRadarPlugin extends AbstractHarnessPlugin {
    public static final String PLUGIN_ID = "dsh-java-dep-plugin";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    public DshDependencyRadarPlugin() {
        super(PLUGIN_ID);
    }

    @Override
    public List<ToolDefinition> tools() {
        return List.of(
                new ParseTreeTool(),
                new FindConflictsTool(),
                new OutdatedTool(),
                new CveScanTool(),
                new UpgradePathTool()
        );
    }

    @Override
    public void configure(PluginContext context) {
        super.configure(context);
        context.registerSystemPrompt("dep-dependencyradar-capabilities", 20, """
                ## DSH DependencyRadar Plugin
                - 全部 5 个工具只读：解析、冲突、过期、CVE 提示、升级路径，不执行任何升级、不联网拉包。
                - CVE 结论是本地启发式关键词表，必须提醒用户以官方 CVE 数据库为准，禁止断言"一定存在漏洞"。
                - dep_outdated/dep_cve_scan/dep_upgrade_path 的 deps 参数接受对象数组或 JSON 字符串。
                - 红线：不生成自动执行的升级脚本、不修改 pom.xml/build.gradle 文件。
                """);
        context.registerHook("PRE_TOOL_USE", (toolName, payloadJson) -> {
            if (toolName != null && toolName.startsWith("plugin__" + PLUGIN_ID + "__dep_")) {
                return PluginHookResult.context("DSH DependencyRadar audit: read-only analysis, never executes upgrades.");
            }
            return null;
        });
    }

    private String post(String path, String json, Map<String, Object> args) {
        String adminUrl = baseUrl(args);
        return send(HttpRequest.newBuilder(URI.create(adminUrl + path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json))
                .build());
    }

    private String baseUrl(Map<String, Object> args) {
        Object override = args == null ? null : args.get("adminBaseUrl");
        return override == null || String.valueOf(override).isBlank()
                ? System.getenv().getOrDefault("DSH_DEP_ADMIN_URL", "http://127.0.0.1:8097")
                : String.valueOf(override);
    }

    private String send(HttpRequest request) {
        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                return failJson(response.statusCode(), response.body());
            }
            return response.body();
        } catch (Exception e) {
            return failJson(0, e.getMessage());
        }
    }

    private String failJson(int status, String message) {
        return "{\"error\":true,\"status\":" + status + ",\"message\":\"" + json(message) + "\"}";
    }

    private String json(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private String str(Map<String, Object> args, String key) {
        Object value = args == null ? null : args.get(key);
        return value == null ? "" : String.valueOf(value);
    }

    /** 把 args 里的 list/array 字段序列化为 JSON 数组字符串；兼容 AI 传 JSON 字符串的形态。 */
    private String listFieldJson(Map<String, Object> args, String field) {
        Object raw = args == null ? null : args.get(field);
        if (raw instanceof List<?> list) {
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object o : list) {
                if (!first) sb.append(",");
                if (o instanceof Map<?, ?> m) {
                    sb.append("{");
                    boolean f2 = true;
                    for (Map.Entry<?, ?> e : m.entrySet()) {
                        if (!f2) sb.append(",");
                        sb.append("\"").append(json(String.valueOf(e.getKey()))).append("\":\"")
                                .append(json(String.valueOf(e.getValue()))).append("\"");
                        f2 = false;
                    }
                    sb.append("}");
                } else {
                    sb.append("\"").append(json(String.valueOf(o))).append("\"");
                }
                first = false;
            }
            return sb.append("]").toString();
        }
        if (raw instanceof String s && !s.isBlank()) {
            String t = s.strip();
            if (t.startsWith("[")) return t;
            // 逐行 "ga=group:artifact, version=x" 或 "group:artifact:x" 文本 → 数组
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (String line : t.replace("\r\n", "\n").split("\n")) {
                String ln = line.strip();
                if (ln.isEmpty()) continue;
                String ga = null, version = null;
                // 形如 group:artifact:version
                String[] parts = ln.split(":");
                if (parts.length >= 3 && !parts[0].contains("=")) {
                    ga = parts[0] + ":" + parts[1];
                    version = parts[parts.length - 1];
                } else {
                    for (String kv : ln.split("[,;]")) {
                        String[] p = kv.split("=", 2);
                        if (p.length != 2) continue;
                        String k = p[0].strip();
                        if (k.equals("ga")) ga = p[1].strip();
                        if (k.equals("version")) version = p[1].strip();
                    }
                }
                if (ga == null || version == null) continue;
                if (!first) sb.append(",");
                sb.append("{\"ga\":\"").append(json(ga)).append("\",\"version\":\"").append(json(version)).append("\"}");
                first = false;
            }
            return sb.append("]").toString();
        }
        return "[]";
    }

    /** 把 args 里的 map 字段序列化为 JSON 对象；兼容 JSON 字符串形态。 */
    private String mapFieldJson(Map<String, Object> args, String field) {
        Object raw = args == null ? null : args.get(field);
        if (raw instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(json(String.valueOf(e.getKey()))).append("\":\"")
                        .append(json(String.valueOf(e.getValue()))).append("\"");
                first = false;
            }
            return sb.append("}").toString();
        }
        if (raw instanceof String s && s.strip().startsWith("{")) return s.strip();
        return "{}";
    }

    private String textPayload(Map<String, Object> args) {
        return "{\"text\":\"" + json(str(args, "text")) + "\",\"format\":\"" + json(str(args, "format")) + "\"}";
    }

    private class ParseTreeTool extends AbstractTool {
        @Override public String name() { return "dep_parse_tree"; }
        @Override public String description() { return "解析 Maven/Gradle 依赖树文本为结构化节点（group/artifact/version/scope/depth）。用户粘贴 dependency:tree 或 gradle dependencies 输出时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("text", stringSchema("依赖树全文文本"))
                    .prop("format", stringSchema("可选：maven/gradle/auto，默认 auto"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址，默认 http://127.0.0.1:8097"))
                    .required("text")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/dep/parse", textPayload(args), args));
        }
    }

    private class FindConflictsTool extends AbstractTool {
        @Override public String name() { return "dep_find_conflicts"; }
        @Override public String description() { return "找版本冲突：同一 group:artifact 出现多个版本，输出冲突列表与统一版本建议。排查 NoSuchMethodError/ClassNotFoundException 时调用。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("text", stringSchema("依赖树全文文本"))
                    .prop("format", stringSchema("可选：maven/gradle/auto"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("text")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/dep/conflicts", textPayload(args), args));
        }
    }

    private class OutdatedTool extends AbstractTool {
        @Override public String name() { return "dep_outdated"; }
        @Override public String description() { return "过期依赖检查：与内置最新版本表对比（可传 latest 覆盖），输出 up-to-date/outdated/unknown 状态。deps 形如 [{\"ga\":\"group:artifact\",\"version\":\"1.0\"}]。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("deps", stringSchema("依赖清单数组，如 [{\"ga\":\"com.google.guava:guava\",\"version\":\"29.0-jre\"}]；也接受每行 group:artifact:version 文本"))
                    .prop("latest", stringSchema("可选，最新版本覆盖表 {\"ga\":\"version\"}"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("deps")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            String body = "{\"deps\":" + listFieldJson(args, "deps") + ",\"latest\":" + mapFieldJson(args, "latest") + "}";
            return ok(post("/api/dep/outdated", body, args));
        }
    }

    private class CveScanTool extends AbstractTool {
        @Override public String name() { return "dep_cve_scan"; }
        @Override public String description() { return "CVE 关键词扫描（本地启发式表）：jackson-databind/logback/netty/fastjson 等常见高危组件低版本提示，输出 severity 与修复版本。安全审计时调用；结果需注明非真实 CVE 库。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("deps", stringSchema("依赖清单数组，同 dep_outdated"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("deps")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            return ok(post("/api/dep/cve-scan", "{\"deps\":" + listFieldJson(args, "deps") + "}", args));
        }
    }

    private class UpgradePathTool extends AbstractTool {
        @Override public String name() { return "dep_upgrade_path"; }
        @Override public String description() { return "升级路径建议：底层→框架→应用库的升级顺序，含风险级别与回归检查建议。只出计划不执行。target 可指定目标版本表。"; }
        @Override public Map<String, Object> parameters() {
            return objectSchema()
                    .prop("deps", stringSchema("依赖清单数组，同 dep_outdated"))
                    .prop("target", stringSchema("可选，目标版本表 {\"ga\":\"version\"}，缺省用内置最新表"))
                    .prop("adminBaseUrl", stringSchema("可选，后台地址"))
                    .required("deps")
                    .build();
        }
        @Override public boolean isConcurrencySafe(Object args) { return true; }
        @Override protected java.util.concurrent.CompletableFuture<cn.xiaofuge.deepseek.harness.domain.model.entity.ToolExecutionResult>
        run(Map<String, Object> args, cn.xiaofuge.deepseek.harness.domain.model.entity.ToolRunContext ctx) {
            String body = "{\"deps\":" + listFieldJson(args, "deps") + ",\"target\":" + mapFieldJson(args, "target") + "}";
            return ok(post("/api/dep/upgrade-path", body, args));
        }
    }
}
