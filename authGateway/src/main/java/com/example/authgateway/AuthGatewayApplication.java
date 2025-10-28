package com.example.authgateway;

import com.example.infra.annotation.EnablePasswordEncoderConfig;
import com.example.infra.annotation.EnableRedisConfig;
import com.example.infra.annotation.EnableWebConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableWebConfig
@EnablePasswordEncoderConfig
@EnableRedisConfig
public class AuthGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthGatewayApplication.class, args);
    }

}
