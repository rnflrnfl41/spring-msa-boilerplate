package com.example.util;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 공통 상수 클래스
 * application-common.yml 파일의 설정값을 자동으로 주입받음
 * 
 * yml 파일 위치: commonLib/src/main/resources/application-common.yml
 * 
 * 사용법:
 * 1. 각 서비스의 application.yml에서 spring.config.import로 참조
 * 2. Java 코드에서는 Constants.상수명으로 직접 사용
 * 3. 설정 변경 시 application-common.yml만 수정하면 자동 반영
 */
@Component
public class Constants {
    
    // ===== 서버 포트 =====
    @Value("${app.ports.auth-server}")
    public static int AUTH_SERVER_PORT;
    
    @Value("${app.ports.auth-gateway}")
    public static int AUTH_GATEWAY_PORT;
    
    @Value("${app.ports.api-gateway}")
    public static int API_GATEWAY_PORT;
    
    @Value("${app.ports.eureka}")
    public static int EUREKA_PORT;
    
    @Value("${app.ports.frontend}")
    public static int FRONTEND_PORT;
    
    // ===== 기본 URL =====
    @Value("${app.base-url}")
    public static String BASE_URL;
    
    // ===== 서비스 이름 =====
    @Value("${app.service-names.auth-server}")
    public static String AUTH_SERVICE_NAME;
    
    @Value("${app.service-names.auth-gateway}")
    public static String AUTH_GATEWAY_NAME;
    
    @Value("${app.service-names.api-gateway}")
    public static String API_GATEWAY_NAME;
    
    @Value("${app.service-names.eureka}")
    public static String EUREKA_SERVER_NAME;
    
    // ===== URL 조합 메서드들 =====
    public static String getAuthServerUrl() {
        return BASE_URL + ":" + AUTH_SERVER_PORT;
    }
    
    public static String getAuthGatewayUrl() {
        return BASE_URL + ":" + AUTH_GATEWAY_PORT;
    }
    
    public static String getApiGatewayUrl() {
        return BASE_URL + ":" + API_GATEWAY_PORT;
    }
    
    public static String getEurekaUrl() {
        return BASE_URL + ":" + EUREKA_PORT;
    }
    
    public static String getFrontendUrl() {
        return BASE_URL + ":" + FRONTEND_PORT;
    }
}
