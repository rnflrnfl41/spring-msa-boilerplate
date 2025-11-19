package com.example.authserver.handler;

import com.example.authserver.config.CustomRequestCache;
import com.example.authserver.entity.CustomUserDetails;
import com.example.authserver.entity.UserInfo;
import com.example.authserver.handler.info.OAuth2UserInfo;
import com.example.authserver.handler.info.OAuth2UserInfoFactory;
import com.example.authserver.config.properties.AppProperties;
import com.example.authserver.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final AppProperties appProperties;
    private final CustomRequestCache customRequestCache;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String provider = oauthToken.getAuthorizedClientRegistrationId(); // google, kakao ...

        OAuth2UserInfo userInfo =
                OAuth2UserInfoFactory.of(oauthToken.getAuthorizedClientRegistrationId(),
                        oauthToken.getPrincipal().getAttributes());

        // ✅ 사용자 정보 추출
        String email = userInfo.getEmail();
        String name = userInfo.getName();
        String providerId = userInfo.getId();

        log.info("소셜 로그인 성공 [{}]: email={}, name={}, providerId={}", provider, email, name, providerId);

        // ✅ 유저 존재 여부 확인
        Optional<UserInfo> existingSocial = userRepository.findByEmailAndProviderAndProviderId(email,provider,providerId);

        if (existingSocial.isEmpty()) {
            log.info("신규 소셜 사용자, 추가정보 입력 필요 email: {} provider: {} providerId: {}", email,provider,providerId);

            // 2-3. 추가 정보 입력 페이지로 리다이렉트
            String signupUrl = appProperties.getSignupUrl() + "?social=true&provider=" + provider + "&providerId=" + providerId + "&email=" + email;
            getRedirectStrategy().sendRedirect(request, response, signupUrl);
            return;
        }

        UserInfo user = userRepository.findByEmailAndProviderAndProviderId(
                userInfo.getEmail(),
                oauthToken.getAuthorizedClientRegistrationId(),
                userInfo.getId()
        ).orElseThrow();

        // CustomUserDetails 생성
        CustomUserDetails customPrincipal = new CustomUserDetails(user, oauthToken.getPrincipal().getAttributes());

        // OAuth2AuthenticationToken → UsernamePasswordAuthenticationToken 로 교체
        UsernamePasswordAuthenticationToken newAuth =
                new UsernamePasswordAuthenticationToken(
                        customPrincipal,
                        null,
                        customPrincipal.getAuthorities()
                );

        // SecurityContext에 저장
        SecurityContextHolder.getContext().setAuthentication(newAuth);

        // ✅ 3️⃣ 기존 회원이면 정상 리다이렉트
        SavedRequest savedRequest = customRequestCache.getRequest(request, response);
        String redirectUrl = (savedRequest != null)
                ? savedRequest.getRedirectUrl()
                : appProperties.getFrontendDashBoardUrl();

        getRedirectStrategy().sendRedirect(request, response, redirectUrl);
    }
}
