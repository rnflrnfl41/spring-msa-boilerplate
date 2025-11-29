package com.example.webbffserver.service;

import com.example.webbffserver.config.AppProperties;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final AppProperties appProperties;
    private final WebClient webClient;
    private final TokenService tokenService;



    /**
     * 사용자 정보 조회 (JWT 토큰에서 직접 추출)
     * 토큰 만료 시 자동 갱신 후 재시도
     */
    public Map<String, Object> getUserInfo(String accessToken, HttpServletRequest req, HttpServletResponse res) {

        try {
            // 1차 시도
            Map<String, Object> userInfo = webClient.get()
                    .uri(appProperties.getAuthServerUserInfoUrl())
                    .headers(headers -> headers.setBearerAuth(accessToken))
                    .exchangeToMono(response -> {
                        if (response.statusCode() == HttpStatus.UNAUTHORIZED) {
                            log.warn("⚠️ Auth Server에서 401 응답, 토큰 만료 가능성 - 에러 응답 파싱");
                            return response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                                    .doOnNext(errorBody -> {
                                        String error = (String) errorBody.getOrDefault("error", "");
                                        log.warn("⚠️ 401 에러 상세: {}", error);
                                    });
                        } else if (response.statusCode().is4xxClientError()) {
                            return response.bodyToMono(String.class)
                                    .doOnNext(body -> log.error("📩 4xx 응답 내용: {}", body))
                                    .flatMap(body -> Mono.error(new RuntimeException("4xx Client Error: " + body)));
                        } else if (response.statusCode().is2xxSuccessful()) {
                            return response.bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {});
                        } else {
                            return response.bodyToMono(String.class)
                                    .flatMap(body -> Mono.error(new RuntimeException("Unexpected status: " + response.statusCode())));
                        }
                    })
                    .block();

            // 401 에러로 error 필드가 있거나 null인 경우 토큰 갱신 후 재시도
            if (req != null && res != null) {
                boolean shouldRefresh = false;
                String error = null;

                if (userInfo == null) {
                    shouldRefresh = true;
                } else if (userInfo.containsKey("error")) {
                    error = (String) userInfo.get("error");
                    if ("invalid_token".equals(error) || "expired_token".equals(error)) {
                        shouldRefresh = true;
                    }
                }

                if (shouldRefresh) {
                    log.info("🔄 토큰 만료로 인한 401 응답 (error: {}), 자동 갱신 후 재시도", error);
                    String newToken = tokenService.refreshToken(req, res);
                    if (newToken != null) {
                        // 새 토큰으로 재시도
                        if (newToken != null) {
                            log.info("✅ 토큰 갱신 성공, userInfo 재요청");
                            return webClient.get()
                                    .uri(appProperties.getAuthServerUserInfoUrl())
                                    .headers(headers -> headers.setBearerAuth(newToken))
                                    .retrieve()
                                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                                    .block();
                        }
                    }
                    log.error("❌ 토큰 갱신 실패 또는 새 토큰을 가져올 수 없음");
                    return null;
                }
            }

            // 정상 응답인 경우 그대로 반환
            return userInfo;

        } catch (WebClientResponseException.Unauthorized e) {
            log.error("❌ Auth Server 인증 실패: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            log.error("❌ userInfo 조회 실패: {}", e.getMessage());
            return null;
        }
    }

}
