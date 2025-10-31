package com.example.authserver;

import com.example.infra.annotation.EnablePasswordEncoderConfig;
import com.example.infra.annotation.EnableRedisConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnablePasswordEncoderConfig
@EnableRedisConfig
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }

}
