package com.example.webbffserver.service;

import com.example.webbffserver.config.AppProperties;
import com.example.webbffserver.dto.TokenResponse;
import com.example.webbffserver.utils.CookieUtil;

import static com.example.webbffserver.utils.CookieUtil.ACCESS_TOKEN_COOKIE;
import static com.example.webbffserver.utils.CookieUtil.REFRESH_TOKEN_COOKIE;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenService {

    private final AppProperties appProperties;

    private final WebClient webClient;

    /**
     * OAuth2 Authorization Server에서 토큰 교환
     */
    public TokenResponse exchangeToken(String authorizationCode) {
        try {
            return webClient.post()
                    .uri(appProperties.getAuthServerTokenUrl())
                    .headers(h -> h.setBasicAuth("bff-client", "bff-secret"))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                            .with("code", authorizationCode)
                            .with("redirect_uri", appProperties.getAuthGatewayCallbackUrl())
                            .with("client_id", "bff-client"))
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, res -> {
                        log.error("❌ 4xx 클라이언트 오류 발생: {}", res.statusCode());
                        return res.bodyToMono(String.class)
                                .doOnNext(body -> log.error("📩 4xx 응답 내용: {}", body))
                                .map(RuntimeException::new);
                    })
                    .onStatus(HttpStatusCode::is5xxServerError, res -> {
                        log.error("❌ 5xx 서버 오류 발생: {}", res.statusCode());
                        return res.bodyToMono(String.class)
                                .doOnNext(body -> log.error("📩 5xx 응답 내용: {}", body))
                                .map(RuntimeException::new);
                    })
                    .bodyToMono(TokenResponse.class)
                    .doOnNext(t -> {
                        String token = t.getAccessToken();
                        if (token != null && !token.isEmpty()) {
                            log.info("✅ 토큰 교환 성공: {}", token.length() > 20
                                    ? token.substring(0, 20) + "..."
                                    : token);
                        } else {
                            log.warn("⚠️ access_token 값이 비어 있습니다: {}", t);
                        }
                    })
                    .block();

        } catch (WebClientResponseException e) {
            log.error("❌ WebClient 오류: {} - {}", e.getStatusCode(), e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("❌ 토큰 교환 중 예외 발생: {}", e.getMessage());
        }
        return null;
    }


    public String refreshToken(HttpServletRequest req, HttpServletResponse res) {
        String refreshToken = CookieUtil.getCookie(req, "REFRESH_TOKEN");
        
        if (refreshToken == null){
            log.error("❌ Refresh 토큰 없음");
            return null;
        } 

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", "refresh_token");
        formData.add("refresh_token", refreshToken);
        formData.add("client_id", "bff-client");

        try {
            Map<String, Object> tokenResponse = webClient.post()
                    .uri(appProperties.getAuthServerTokenUrl())
                    .headers(headers -> {
                        headers.setBasicAuth("bff-client", "bff-secret");
                        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
                    })
                    .body(BodyInserters.fromFormData(formData))
                    .retrieve()
                    .onStatus(HttpStatusCode::isError, clientResponse -> {
                        log.error("❌ Refresh 요청 실패: {}", clientResponse.statusCode());
                        return Mono.error(new RuntimeException("Token refresh failed"));
                    })
                    .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {
                    })
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return null;
            }

            String newAccess = (String) tokenResponse.get("access_token");
            String newRefresh = (String) tokenResponse.getOrDefault("refresh_token", refreshToken);

            CookieUtil.addTokenCookies(res, newAccess, newRefresh, false);
            log.info("✅ Refresh 성공, 새 AccessToken 발급 완료");
            return newAccess;

        } catch (Exception e) {
            log.error("❌ Refresh 중 예외 발생: {}, 토큰 제거 처리", e.getMessage());
            CookieUtil.clearTokenCookies(res, false);
            return null;
        }
    }

    /**
     * 사용자 정보 조회 (JWT 토큰에서 직접 추출)
     * 토큰 만료 시 자동 갱신 후 재시도
     */
    //TODO: 토큰 만료시 재발급 까지는 되는대 해당 토큰으로 auth server에서 인증이 안됌 확인후 수정 해야함
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
                    String newToken = refreshToken(req, res);
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

    /**
     * JWT 토큰 만료 여부 확인
     */
    public boolean isTokenExpired(JWTClaimsSet claimsSet) {
        try {
            if (claimsSet == null || claimsSet.getExpirationTime() == null) {
                return true;
            }
            // 30초 여유 시간을 두고 만료 확인 (만료 직전에도 갱신)
            long now = System.currentTimeMillis();
            long expirationTime = claimsSet.getExpirationTime().getTime();
            return expirationTime <= (now + 30000); // 30초 전부터 만료로 간주
        } catch (Exception e) {
            log.error("❌ 토큰 만료 시간 확인 실패: {}", e.getMessage());
            return true; // 확인할 수 없으면 만료된 것으로 처리
        }
    }

    /**
     * 토큰이 만료되었는지 확인 (토큰 문자열로)
     */
    public boolean isTokenExpired(String token) {
        if (token == null || token.isEmpty()) {
            return true;
        }
        JWTClaimsSet claimsSet = parseToken(token);
        return isTokenExpired(claimsSet);
    }

    public JWTClaimsSet parseToken(String token) {
        try {
            JWT jwt = JWTParser.parse(token);
            return jwt.getJWTClaimsSet();
        } catch (Exception e) {
            log.error("❌ 토큰 파싱 실패: {}", e.getMessage());
            return null;
        }
    }

}
