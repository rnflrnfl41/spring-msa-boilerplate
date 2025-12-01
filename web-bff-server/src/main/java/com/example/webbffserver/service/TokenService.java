package com.example.webbffserver.service;

import com.example.webbffserver.config.AppProperties;
import com.example.webbffserver.dto.TokenResponse;
import com.example.webbffserver.utils.CookieUtil;

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
import java.util.Objects;

import static com.example.webbffserver.utils.CookieUtil.*;

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
            String jSessionId = CookieUtil.getCookie(req, JSESSIONID_COOKIE);

            try {

                webClient.post()
                        .uri(appProperties.getAuthServerLogoutUrl())
                        .cookie(JSESSIONID_COOKIE, Objects.requireNonNull(jSessionId))
                        .retrieve()
                        .toBodilessEntity()
                        .block();

            } catch (Exception logoutEx) {
                log.warn("⚠️ Auth Server 로그아웃 호출 실패: {}", logoutEx.getMessage());
            }

            log.info("🔄 RefreshToken 만료로 인한 세션 삭제, 재인증 필요");
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
