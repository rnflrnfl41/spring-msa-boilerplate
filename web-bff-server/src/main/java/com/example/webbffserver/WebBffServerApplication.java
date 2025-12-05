package com.example.webbffserver;

import com.example.infra.annotation.EnablePasswordEncoderConfig;
import com.example.infra.annotation.EnableWebClientConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@EnablePasswordEncoderConfig
@EnableWebClientConfig
public class WebBffServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebBffServerApplication.class, args);
    }

}
