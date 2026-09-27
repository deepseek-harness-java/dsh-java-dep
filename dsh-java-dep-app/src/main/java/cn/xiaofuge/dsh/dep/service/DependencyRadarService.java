package cn.xiaofuge.dsh.dep.service;

import cn.xiaofuge.dsh.dep.model.ApiException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dependency Radar 依赖雷达：
 * - 解析 Maven 依赖树文本（mvn dependency:tree 输出）为结构化节点
 * - 找版本冲突：同 groupId:artifactId 多版本
 * - 过期依赖：与"最新版本表"对比（内置样例 + 传入覆盖）
 * - CVE 关键词扫描：内置已知漏洞关键词表（本地启发式，非真实 CVE 库）
 * - 升级路径：给出由底层的升级顺序建议
 * 红线：不执行升级、不联网拉包。
 */
@Service
public class DependencyRadarService {

    /** mvn dependency:tree 行：[INFO] +- group:artifact:jar:version:scope（容忍 [INFO]/[DEBUG] 等前缀） */
    private static final Pattern TREE_LINE = Pattern.compile(
            "^(?:\\[[A-Z]+\\])?[\\s|+\\\\-]*([\\w.\\-]+):([\\w.\\-]+):(jar|pom|bundle):([\\w.\\-\\d]+)(?::(compile|runtime|test|provided|system))?\\s*$");
    /** Gradle 行：+--- group:artifact:version */
    private static final Pattern GRADLE_LINE = Pattern.compile(
            "^(?:[A-Z]+)?[\\\\+\\-|\\s]*([\\w.\\-]+):([\\w.\\-]+):([\\w.\\-\\d]+)\\s*$");

    /** 内置"最新版本"样例表（演示用途，可被请求传入的 latest 覆盖）。 */
    private static final Map<String, String> LATEST_KNOWN = Map.ofEntries(
            Map.entry("com.fasterxml.jackson.core:jackson-databind", "2.17.1"),
            Map.entry("org.springframework.boot:spring-boot-starter-web", "3.3.5"),
            Map.entry("org.springframework.boot:spring-boot-starter", "3.3.5"),
            Map.entry("com.google.guava:guava", "33.2.1-jre"),
            Map.entry("org.apache.commons:commons-lang3", "3.14.0"),
            Map.entry("org.slf4j:slf4j-api", "2.0.13"),
            Map.entry("ch.qos.logback:logback-classic", "1.5.6"),
            Map.entry("junit:junit", "4.13.2"),
            Map.entry("org.junit.jupiter:junit-jupiter", "5.10.2"),
            Map.entry("com.alibaba:fastjson", "2.0.57"),
            Map.entry("org.projectlombok:lombok", "1.18.32"),
            Map.entry("io.netty:netty-all", "4.1.111.Final"),
            Map.entry("org.apache.httpcomponents:httpclient", "4.5.14"),
            Map.entry("mysql:mysql-connector-java", "8.0.33"));

    /** 内置 CVE 关键词提示表：坐标关键词 → 提示（演示用途，本地启发式）。 */
    private static final Map<String, Map<String, Object>> CVE_HINTS = buildCveHints();

    public Map<String, Object> parseTree(String text, String format) {
        if (text == null || text.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "text 不能为空");
        }
        String f = format == null ? "auto" : format.toLowerCase();
        List<Map<String, Object>> nodes = new ArrayList<>();
        Map<String, List<String>> versions = new LinkedHashMap<>();
        int depthMax = 0;
        for (String line : text.replace("\r\n", "\n").split("\n")) {
            String t = line.strip();
            if (t.isEmpty()) continue;
            // Maven omitted/冲突标注三种形态：
            // a) 坐标被括号包裹：[INFO] |  \- (ga:art:jar:ver:scope - omitted for conflict)
            // b) 尾注在括号里：ga:art:jar:ver:scope (x - omitted for ...)
            // c) 纯尾注：ga:art:jar:ver:scope - omitted for ...
            java.util.regex.Matcher omitWrapped = Pattern.compile(
                    "^((?:\\[[A-Z]+\\])?[\\s|+\\\\\\-]*)\\((.+)\\)\\s*(?:-\\s*omitted.*)?$").matcher(t);
            if (omitWrapped.matches() && omitWrapped.group(2).contains(":")) {
                t = omitWrapped.group(1) + omitWrapped.group(2);
            }
            int paren = t.indexOf(" (");
            if (paren > 0 && (t.contains("omitted") || t.contains("(*)"))) t = t.substring(0, paren).strip();
            int dashNote = t.indexOf(" - omitted");
            if (dashNote > 0) t = t.substring(0, dashNote).strip();
            if (t.endsWith(";")) t = t.substring(0, t.length() - 1);
            Matcher m = null;
            boolean gradle = false;
            if (!f.equals("gradle")) {
                Matcher mvn = TREE_LINE.matcher(t);
                if (mvn.matches()) m = mvn;
            }
            if (m == null && !f.equals("maven")) {
                Matcher g = GRADLE_LINE.matcher(t);
                if (g.matches()) { m = g; gradle = true; }
            }
            if (m == null) continue;
            String group, artifact, version, scope;
            if (gradle) {
                group = m.group(1);
                artifact = m.group(2);
                version = m.group(3);
                scope = "compile";
            } else {
                group = m.group(1);
                artifact = m.group(2);
                version = m.group(4);
                scope = m.group(5) == null ? "compile" : m.group(5);
            }
            int depth = countDepth(line);
            depthMax = Math.max(depthMax, depth);
            Map<String, Object> node = new LinkedHashMap<>();
            node.put("group", group);
            node.put("artifact", artifact);
            node.put("version", version);
            node.put("scope", scope);
            node.put("depth", depth);
            node.put("ga", group + ":" + artifact);
            nodes.add(node);
            versions.computeIfAbsent(group + ":" + artifact, k -> new ArrayList<>()).add(version);
        }
        if (nodes.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "未能解析出任何依赖，请确认是 mvn dependency:tree 或 gradle dependencies 输出");
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("nodeCount", nodes.size());
        r.put("maxDepth", depthMax);
        r.put("gaCount", versions.size());
        r.put("nodes", nodes);
        return r;
    }

    public Map<String, Object> findConflicts(String text, String format) {
        Map<String, Object> parsed = parseTree(text, format);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> nodes = (List<Map<String, Object>>) parsed.get("nodes");
        Map<String, Set<String>> versions = new LinkedHashMap<>();
        for (Map<String, Object> n : nodes) {
            versions.computeIfAbsent(String.valueOf(n.get("ga")), k -> new TreeSet<>())
                    .add(String.valueOf(n.get("version")));
        }
        List<Map<String, Object>> conflicts = new ArrayList<>();
        for (Map.Entry<String, Set<String>> e : versions.entrySet()) {
            if (e.getValue().size() > 1) {
                List<String> vs = new ArrayList<>(e.getValue());
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("ga", e.getKey());
                c.put("versions", vs);
                c.put("count", vs.size());
                conflicts.add(c);
            }
        }
        conflicts.sort((x, y) -> Integer.compare((int) y.get("count"), (int) x.get("count")));
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("gaTotal", versions.size());
        r.put("conflictCount", conflicts.size());
        r.put("conflicts", conflicts);
        r.put("advice", conflicts.isEmpty() ? "无版本冲突" : "建议用 dependencyManagement / platform BOM 统一到单一版本（选最高或经兼容验证的版本）");
        return r;
    }

    public Map<String, Object> outdated(List<Map<String, String>> deps, Map<String, String> latestOverride) {
        if (deps == null || deps.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "deps 不能为空");
        }
        List<Map<String, Object>> items = new ArrayList<>();
        int outdatedCount = 0;
        for (Map<String, String> d : deps) {
            String ga = d.get("ga") != null ? d.get("ga")
                    : (d.get("group") + ":" + d.get("artifact"));
            String current = d.get("version");
            String latest = latestOverride != null && latestOverride.containsKey(ga)
                    ? latestOverride.get(ga) : LATEST_KNOWN.get(ga);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("ga", ga);
            item.put("current", current);
            if (latest == null) {
                item.put("status", "unknown");
                item.put("latest", null);
            } else {
                item.put("latest", latest);
                int cmp = compareVersions(current, latest);
                if (cmp < 0) {
                    item.put("status", "outdated");
                    outdatedCount++;
                } else {
                    item.put("status", "up-to-date");
                }
            }
            items.add(item);
        }
        items.sort(Comparator.comparing(x -> String.valueOf(x.get("status"))));
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("checked", items.size());
        r.put("outdatedCount", outdatedCount);
        r.put("items", items);
        return r;
    }

    public Map<String, Object> cveScan(List<Map<String, String>> deps) {
        if (deps == null || deps.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "deps 不能为空");
        }
        List<Map<String, Object>> hits = new ArrayList<>();
        for (Map<String, String> d : deps) {
            String ga = d.get("ga") != null ? d.get("ga")
                    : (d.get("group") + ":" + d.get("artifact"));
            String version = d.get("version");
            for (Map.Entry<String, Map<String, Object>> hint : CVE_HINTS.entrySet()) {
                if (!ga.contains(hint.getKey())) continue;
                String maxVuln = String.valueOf(hint.getValue().get("affectedBelow"));
                if (compareVersions(version, maxVuln) < 0) {
                    Map<String, Object> h = new LinkedHashMap<>(hint.getValue());
                    h.put("ga", ga);
                    h.put("version", version);
                    h.put("note", "本地启发式提示，非真实 CVE 数据库；升级到 " + hint.getValue().get("fixedIn") + "+ 并以官方通告为准");
                    hits.add(h);
                }
            }
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("checked", deps.size());
        r.put("hitCount", hits.size());
        r.put("hits", hits);
        r.put("disclaimer", "内置关键词表仅覆盖常见高危组件的演示场景，不做真实 CVE 查询、不联网");
        return r;
    }

    public Map<String, Object> upgradePath(List<Map<String, String>> deps, Map<String, String> target) {
        if (deps == null || deps.isEmpty()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "deps 不能为空");
        }
        List<Map<String, Object>> steps = new ArrayList<>();
        int idx = 1;
        for (Map<String, String> d : deps) {
            String ga = d.get("ga") != null ? d.get("ga")
                    : (d.get("group") + ":" + d.get("artifact"));
            String from = d.get("version");
            String to = target != null && target.containsKey(ga) ? target.get(ga) : LATEST_KNOWN.get(ga);
            if (to == null || compareVersions(from, to) >= 0) continue;
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("order", idx++);
            s.put("ga", ga);
            s.put("from", from);
            s.put("to", to);
            s.put("risk", riskLevel(ga));
            s.put("check", "升级后跑回归：" + suggestCheck(ga));
            steps.add(s);
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("stepCount", steps.size());
        r.put("steps", steps);
        r.put("principle", "先升级底层/平台依赖（netty/jackson/logback），再升级框架（spring-boot），最后应用库；每步独立提交+回归。");
        r.put("note", "仅输出升级路径建议，不执行任何升级、不联网拉包");
        return r;
    }

    // ---------- helpers ----------

    private static int countDepth(String line) {
        int depth = 0;
        for (char c : line.toCharArray()) {
            if (c == '|' || c == '+' || c == '\\' || c == '-') depth++;
        }
        return Math.min(depth / 2, 30);
    }

    /** 版本号比较：数字段逐段比较，字母段字典序；长度不同补 0。 */
    private static int compareVersions(String a, String b) {
        if (a == null || b == null) return 0;
        String[] as = a.split("[.\\-_]");
        String[] bs = b.split("[.\\-_]");
        int n = Math.max(as.length, bs.length);
        for (int i = 0; i < n; i++) {
            String x = i < as.length ? as[i] : "0";
            String y = i < bs.length ? bs[i] : "0";
            try {
                int xi = Integer.parseInt(x.replaceAll("\\D", ""));
                int yi = Integer.parseInt(y.replaceAll("\\D", ""));
                if (xi != yi) return Integer.compare(xi, yi);
            } catch (NumberFormatException ignored) {
                int c = x.compareTo(y);
                if (c != 0) return c;
            }
        }
        return 0;
    }

    private static String riskLevel(String ga) {
        if (ga.contains("netty") || ga.contains("jackson") || ga.contains("logback")) return "high-impact(底层)";
        if (ga.contains("spring-boot")) return "medium(框架级，统一升级)";
        return "low(应用库)";
    }

    private static String suggestCheck(String ga) {
        if (ga.contains("jackson")) return "JSON 序列化回归（日期/多态/未知字段）";
        if (ga.contains("netty")) return "网络层压测 + 连接池泄漏观测";
        if (ga.contains("logback")) return "日志格式与 appender 输出检查";
        if (ga.contains("spring-boot")) return "全量接口冒烟 + 配置项兼容检查";
        return "相关模块单测 + 冒烟";
    }

    private static Map<String, Map<String, Object>> buildCveHints() {
        Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        m.put("jackson-databind", Map.of(
                "cveHint", "CVE-2020-36518 等（深嵌套 JSON 反序列化 DoS / 多态反序列化 RCE 系列）",
                "affectedBelow", "2.12.6", "fixedIn", "2.12.7.1", "severity", "high"));
        m.put("logback", Map.of(
                "cveHint", "CVE-2023-6378 / CVE-2021-42550（receiver 反序列化 / JNDI）",
                "affectedBelow", "1.2.9", "fixedIn", "1.3.0", "severity", "high"));
        m.put("netty", Map.of(
                "cveHint", "CVE-2021-21290 / CVE-2019-20444（临时文件权限 / HTTP 请求走私 DoS）",
                "affectedBelow", "4.1.59", "fixedIn", "4.1.60", "severity", "high"));
        m.put("httpclient", Map.of(
                "cveHint", "CVE-2020-13956（URI 解析误判）",
                "affectedBelow", "4.5.13", "fixedIn", "4.5.13", "severity", "medium"));
        m.put("mysql-connector-java", Map.of(
                "cveHint", "CVE-2023-21971 等（Connector/J 连接串攻击面）",
                "affectedBelow", "8.0.33", "fixedIn", "8.0.33", "severity", "medium"));
        m.put("fastjson", Map.of(
                "cveHint", "autoType 反序列化 RCE 系列",
                "affectedBelow", "1.2.83", "fixedIn", "2.0.x", "severity", "high"));
        return m;
    }
}
