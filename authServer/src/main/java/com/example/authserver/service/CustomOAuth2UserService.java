package com.example.authserver.service;

import com.example.authserver.entity.CustomUserDetails;
import com.example.authserver.entity.UserInfo;
import com.example.authserver.handler.info.OAuth2UserInfo;
import com.example.authserver.handler.info.OAuth2UserInfoFactory;
import com.example.authserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 3️⃣ Kakao 등 일반 OAuth2 Provider용
 * id, nickname, profile_image 매핑
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest)
            throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.of(provider, oAuth2User.getAttributes());

        // 1) 소셜 계정 DB 조회
        UserInfo user = userRepository
                .findByEmailAndProviderAndProviderId(userInfo.getEmail(),provider, userInfo.getId())
                .orElseThrow(() -> new OAuth2AuthenticationException("소셜 계정을 찾을 수 없음"));

        // 2) CustomUserDetails 로 래핑
        return new CustomUserDetails(user, oAuth2User.getAttributes());
    }
}
