# Auth Gateway (BFF 서버)

## 개요
Auth Gateway는 Backend for Frontend (BFF) 패턴을 구현한 서버입니다. SPA(React/Vue)와 OAuth2 Authorization Server 사이에서 중간 역할을 하며, 보안을 강화하고 토큰 관리를 담당합니다.

## 포트
- **9091**: Auth Gateway (BFF 서버)

## 주요 기능

### 1. 인증 플로우
```
1️⃣ SPA → BFF → Auth Server (Authorization Request)
   SPA가 로그인 버튼 클릭 → BFF 서버의 /login으로 리다이렉트
   BFF가 Auth Server의 /oauth2/authorize로 리다이렉트 (BFF가 클라이언트)

2️⃣ Auth Server → 소셜 로그인 (Google/Kakao)
   Auth Server가 구글/카카오 등 소셜 로그인으로 사용자 인증
   소셜 로그인 성공 시 Auth Server가 OAuth2 Authorization Code 생성

3️⃣ Auth Server → BFF (Authorization Code)
   Auth Server가 Authorization Code를 BFF의 redirect URI로 전달

4️⃣ BFF → Auth Server (Token Request)
   BFF가 Authorization Code를 받아 Auth Server /token 요청
   Auth Server가 Access Token + Refresh Token 발급

5️⃣ SPA → BFF → API 서버 (Access)
   SPA는 로그인 후 BFF의 엔드포인트 호출
   BFF가 Redis에서 Access Token 사용 → API 서버에 요청 + Access Token 포함
```

### 2. API 엔드포인트

#### 인증 관련
- `GET /api/auth/login` - Auth Server로 리다이렉트 (BFF가 Auth Server의 클라이언트)
- `GET /api/auth/status` - 로그인 상태 확인
- `GET /api/auth/user/me` - 사용자 정보 반환
- `POST /api/auth/logout` - 로그아웃 처리

#### API 프록시
- `GET /api/proxy/**` - API 서버로의 GET 요청 프록시
- `POST /api/proxy/**` - API 서버로의 POST 요청 프록시
- `PUT /api/proxy/**` - API 서버로의 PUT 요청 프록시
- `DELETE /api/proxy/**` - API 서버로의 DELETE 요청 프록시

### 3. 토큰 관리
- **Access Token**: 30분간 Redis에 저장
- **Refresh Token**: 7일간 Redis에 저장
- **자동 갱신**: Access Token 만료 시 Refresh Token으로 자동 갱신

### 4. 보안 기능
- **세션 기반**: SPA는 Access Token을 직접 관리하지 않음
- **HttpOnly 쿠키**: 세션 ID를 안전하게 전달
- **CORS 설정**: 프론트엔드 도메인만 허용
- **토큰 프록시**: API 서버로의 모든 요청에 Access Token 자동 추가

## 설정

### Redis 설정
```yaml
spring:
  data:
    redis:
      host: localhost
      port: 6379
      password: 
      timeout: 2000ms
```

### OAuth2 Client 설정
```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          auth-server:
            client-id: bff-client
            client-secret: bff-secret
            authorization-grant-type: authorization_code
            redirect-uri: http://localhost:9091/api/auth/callback
            scope: openid,profile,email
        provider:
          auth-server:
            authorization-uri: http://localhost:9090/oauth2/authorize
            token-uri: http://localhost:9090/oauth2/token
            user-info-uri: http://localhost:9090/userinfo
            jwk-set-uri: http://localhost:9090/.well-known/jwks.json
```

## 사용법

### 1. 서버 시작
```bash
cd authGateway
./gradlew bootRun
```

### 2. SPA에서 로그인
```javascript
// SPA에서 로그인 버튼 클릭 시
window.location.href = 'http://localhost:9091/api/auth/login';
```

### 3. API 호출
```javascript
// 로그인 상태 확인
const response = await fetch('http://localhost:9091/api/auth/status', {
  credentials: 'include' // 쿠키 포함
});

// 사용자 정보 조회
const userInfo = await fetch('http://localhost:9091/api/auth/user/me', {
  credentials: 'include'
});

// API 서버 호출 (프록시)
const data = await fetch('http://localhost:9091/api/proxy/api/users', {
  credentials: 'include'
});
```

## 테스트

`test.http` 파일을 사용하여 API를 테스트할 수 있습니다.

## 의존성
- Spring Boot 3.x
- Spring Security OAuth2 Client
- Spring Data Redis
- Jackson (JSON 처리)
