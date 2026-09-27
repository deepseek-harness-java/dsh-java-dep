package cn.xiaofuge.dsh.dep.controller;

import cn.xiaofuge.dsh.dep.config.DependencyRadarProperties;
import cn.xiaofuge.dsh.dep.model.ApiException;
import cn.xiaofuge.dsh.dep.service.DependencyRadarService;
import cn.xiaofuge.dsh.dep.service.HarnessAiStreamService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;
import java.util.Map;

@RestController
public class DependencyRadarController {
    private final DependencyRadarService depService;
    private final HarnessAiStreamService harnessAiStreamService;
    private final DependencyRadarProperties properties;

    public DependencyRadarController(DependencyRadarService depService,
                                     HarnessAiStreamService harnessAiStreamService,
                                     DependencyRadarProperties properties) {
        this.depService = depService;
        this.harnessAiStreamService = harnessAiStreamService;
        this.properties = properties;
    }

    public record TreeRequest(String text, String format) {
    }

    public record OutdatedRequest(List<Map<String, String>> deps, Map<String, String> latest) {
    }

    public record ScanRequest(List<Map<String, String>> deps) {
    }

    public record UpgradeRequest(List<Map<String, String>> deps, Map<String, String> target) {
    }

    @PostMapping("/api/dep/parse")
    public Map<String, Object> parse(@RequestBody TreeRequest request) {
        return depService.parseTree(request.text(), request.format());
    }

    @PostMapping("/api/dep/conflicts")
    public Map<String, Object> conflicts(@RequestBody TreeRequest request) {
        return depService.findConflicts(request.text(), request.format());
    }

    @PostMapping("/api/dep/outdated")
    public Map<String, Object> outdated(@RequestBody OutdatedRequest request) {
        return depService.outdated(request.deps(), request.latest());
    }

    @PostMapping("/api/dep/cve-scan")
    public Map<String, Object> cveScan(@RequestBody ScanRequest request) {
        return depService.cveScan(request.deps());
    }

    @PostMapping("/api/dep/upgrade-path")
    public Map<String, Object> upgradePath(@RequestBody UpgradeRequest request) {
        return depService.upgradePath(request.deps(), request.target());
    }

    @PostMapping(value = "/api/assistant/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter assistant(@RequestBody Map<String, String> request) {
        String agentId = request.getOrDefault("agentId", "");
        String message = request.getOrDefault("message", "");
        if (agentId.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "agentId 不能为空");
        }
        if (message.isBlank()) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "message 不能为空");
        }
        return harnessAiStreamService.stream(agentId, buildPrompt(message));
    }

    private String buildPrompt(String message) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("当前环境：\n");
        prompt.append("- Dependency Radar（依赖雷达）：解析依赖树、找版本冲突、过期检查、CVE 关键词扫描、升级路径\n");
        prompt.append("- 你可以使用以下工具查证（涉及依赖分析时必须先调用工具，禁止凭记忆断言版本状态）：\n");
        prompt.append("  - plugin__dsh-java-dep__dep_parse_tree(text, format?)：解析 mvn/gradle 依赖树文本\n");
        prompt.append("  - plugin__dsh-java-dep__dep_find_conflicts(text, format?)：同坐标多版本冲突\n");
        prompt.append("  - plugin__dsh-java-dep__dep_outdated(deps, latest?)：过期依赖对比（内置最新版本表）\n");
        prompt.append("  - plugin__dsh-java-dep__dep_cve_scan(deps)：CVE 关键词扫描（本地启发式表）\n");
        prompt.append("  - plugin__dsh-java-dep__dep_upgrade_path(deps, target?)：升级顺序建议\n");
        prompt.append("\n用户需求：").append(message);
        prompt.append("\n\n回答要求：\n");
        prompt.append("- 使用中文，Markdown 格式，结论先行。\n");
        prompt.append("- CVE 结论必须注明是本地启发式提示，建议用户以官方 CVE 数据库通告为准。\n");
        prompt.append("- 红线：不执行任何升级命令、不联网拉包、不生成会自动执行的升级脚本。\n");
        return prompt.toString();
    }
}
