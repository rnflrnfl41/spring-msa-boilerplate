package com.example.webbffserver.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.experimental.UtilityClass;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@UtilityClass
public class CookieUtil {

    // 쿠키 이름 (한 곳에서만 관리)
    public static final String ACCESS_TOKEN_COOKIE  = "ACCESS_TOKEN";
    public static final String REFRESH_TOKEN_COOKIE = "REFRESH_TOKEN";
    public static final String JSESSIONID_COOKIE = "JSESSIONID";

    // 기본 수명 (필요 시 yml로 뺄 수 있음)
    private static final int ACCESS_MAX_AGE_SECONDS  = 60 * 30;         // 30분
    private static final int REFRESH_MAX_AGE_SECONDS = 60 * 60 * 24 * 14; // 14일

    /**
     * 액세스/리프레시 토큰을 HttpOnly 쿠키로 저장.
     * @param secure  배포(HTTPS)에서는 true 필수 (SameSite=None과 함께)
     * @param sameSite "Lax" | "Strict" | "None" (개발: Lax, 배포: None 권장)
     * @param domain   예: "myapp.com" (서브도메인 공유 필요 시), 없다면 null
     */
    public static void addTokenCookies(HttpServletResponse res,
                                       String accessToken,
                                       String refreshToken,
                                       boolean secure,
                                       String sameSite,
                                       String domain) {
        addCookie(res, ACCESS_TOKEN_COOKIE,  accessToken,  ACCESS_MAX_AGE_SECONDS,  secure, sameSite, domain);
        addCookie(res, REFRESH_TOKEN_COOKIE, refreshToken, REFRESH_MAX_AGE_SECONDS, secure, sameSite, domain);
    }

    /** 오버로드: sameSite=Lax, domain 미설정(로컬 개발 괜찮음) */
    public static void addTokenCookies(HttpServletResponse res,
                                       String accessToken,
                                       String refreshToken,
                                       boolean secure) {
        addTokenCookies(res, accessToken, refreshToken, secure, "Lax", null);
    }

    /** 쿠키 삭제 (로그아웃 등) */
    public static void clearTokenCookies(HttpServletResponse res, boolean secure, String domain) {
        addCookie(res, ACCESS_TOKEN_COOKIE,  "", 0, secure, "Lax", domain);
        addCookie(res, REFRESH_TOKEN_COOKIE, "", 0, secure, "Lax", domain);
    }

    public static void clearTokenCookies(HttpServletResponse res, boolean secure) {
        clearTokenCookies(res, secure, null);
    }

    /** 요청에서 특정 쿠키 값 읽기 */
    public static String getCookie(HttpServletRequest req, String name) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) {
                return URLDecoder.decode(c.getValue(), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    // --- 내부 공통 ---

    private static void addCookie(HttpServletResponse res,
                                  String name,
                                  String value,
                                  int maxAgeSeconds,
                                  boolean secure,
                                  String sameSite,
                                  String domain) {
        // javax.servlet Cookie는 SameSite를 직접 지원하지 않아서 Set-Cookie 헤더로 작성
        // (Spring 6+라면 ResponseCookie 사용 가능하지만, 여기선 모든 톰캣/서블릿 호환을 위해 문자열로 구성)
        String encoded = URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        sb.append(name).append("=").append(encoded).append("; Path=/");

        if (maxAgeSeconds >= 0) {
            sb.append("; Max-Age=").append(maxAgeSeconds);
        }
        // 배포(서브도메인 공유 필요) 시 설정: .myapp.com
        if (domain != null && !domain.isBlank()) {
            sb.append("; Domain=").append(domain);
        }
        // JS 접근 차단
        sb.append("; HttpOnly");

        // SameSite 지정
        // - Lax: 대부분의 SPA + 리다이렉트 케이스 OK(개발 편함)
        // - None: 크로스사이트 전송(서브도메인/별도 도메인) 필요할 때. 이땐 Secure 필수!
        if (sameSite != null && !sameSite.isBlank()) {
            sb.append("; SameSite=").append(sameSite);
        }

        // HTTPS 환경이면 반드시 Secure
        if (secure || "None".equalsIgnoreCase(sameSite)) {
            sb.append("; Secure");
        }

        res.addHeader("Set-Cookie", sb.toString());
    }
}
