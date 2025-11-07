package com.example.authserver.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

/**
 * 2️⃣ Google OIDC 로그인용
 * sub, email, picture 등 OIDC Claims 매핑
 */
@Component
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);

        // Google OIDC 사용자 정보를 그대로 사용
        // 권한은 SecurityConfig에서 처리
        
        return oidcUser;
    }
}