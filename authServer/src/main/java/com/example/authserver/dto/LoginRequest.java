package com.example.authserver.dto;

/**
 * ========================================
 * 로그인 요청 DTO
 * ========================================
 * 커스텀 로그인 (ID/PW 방식)에서 사용
 */
public class LoginRequest {
    private String email;
    private String password;

    public LoginRequest() {}

    public LoginRequest(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}
