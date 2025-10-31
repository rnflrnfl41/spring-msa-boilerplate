package com.example.webbffserver;

import com.example.infra.annotation.EnablePasswordEncoderConfig;
import com.example.infra.annotation.EnableWebConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnableWebConfig
@EnablePasswordEncoderConfig
public class WebBffServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebBffServerApplication.class, args);
    }

}
