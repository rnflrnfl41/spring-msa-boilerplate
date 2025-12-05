package com.example.webbffserver.config;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class ApiGatewayClient {

    private final WebClient gatewayWebClient;

    public <T> Mono<T> get(String path, Class<T> type) {
        return gatewayWebClient.get()
                .uri(path)
                .retrieve()
                .bodyToMono(type);
    }

    public <T> Mono<T> post(String path, Object body, Class<T> type) {
        return gatewayWebClient.post()
                .uri(path)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(type);
    }
}
