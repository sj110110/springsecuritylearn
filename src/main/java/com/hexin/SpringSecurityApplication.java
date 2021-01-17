package com.hexin;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;

@MapperScan("com.hexin.mapper")
@EnableGlobalMethodSecurity(prePostEnabled = true)
@SpringBootApplication
public class SpringSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityApplication.class, args);
    }
}
