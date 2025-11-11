package com.example.authserver.config.info;

import java.util.Map;

public interface OAuth2UserInfo {

    /** provider에서 받은 원본 attribute 맵 */
    Map<String, Object> getAttributes();

    /** provider가 발급한 고유 ID (Google: sub, Kakao: id 등) */
    String getId();

    /** 이메일 */
    String getEmail();

    /** 사용자 이름 / 닉네임 */
    String getName();
}
