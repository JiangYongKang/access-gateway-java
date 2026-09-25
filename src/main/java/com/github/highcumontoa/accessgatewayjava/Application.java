package com.github.highcumontoa.accessgatewayjava;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.time.Clock;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    /**
     * 统一时钟源：测试中可替换为固定/偏移时钟，保证时钟偏差场景可复现。
     */
    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
