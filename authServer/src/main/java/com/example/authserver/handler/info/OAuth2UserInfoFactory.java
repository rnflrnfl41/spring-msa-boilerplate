package com.example.authserver.handler.info;

import java.util.Map;

public class OAuth2UserInfoFactory {

    public static OAuth2UserInfo of(String provider, Map<String, Object> attributes) {
        return switch (provider.toLowerCase()) {
            case "google" -> new GoogleOAuth2UserInfo(attributes);
            case "kakao" -> new KakaoOAuth2UserInfo(attributes);
            default -> throw new IllegalArgumentException("지원하지 않는 provider: " + provider);
        };
    }
}
