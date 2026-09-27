package cn.xiaofuge.dsh.dep.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "dsh.depradar")
public record DependencyRadarProperties(
        String dataDirectory,
        Harness harness
) {
    public record Harness(String baseUrl) {
    }
}
