package cn.xiaofuge.dsh.dep;

import cn.xiaofuge.dsh.dep.config.DependencyRadarProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(DependencyRadarProperties.class)
public class DshJavaDependencyRadarApplication {

    public static void main(String[] args) {
        SpringApplication.run(DshJavaDependencyRadarApplication.class, args);
    }
}
