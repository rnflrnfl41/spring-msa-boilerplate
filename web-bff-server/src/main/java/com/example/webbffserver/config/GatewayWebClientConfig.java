package com.example.webbffserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
@RequiredArgsConstructor
public class GatewayWebClientConfig {

    private final AppProperties appProperties;

    @Bean
    public WebClient gatewayWebClient(WebClient.Builder builder) {
        return builder
                .baseUrl(appProperties.getApiGatewayUrl())
                .defaultHeader("Content-Type", "application/json")
                .build();
    }
}
