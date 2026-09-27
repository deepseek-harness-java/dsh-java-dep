package cn.xiaofuge.dsh.dep.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(DependencyRadarProperties.class)
public class ApplicationConfiguration {
}
