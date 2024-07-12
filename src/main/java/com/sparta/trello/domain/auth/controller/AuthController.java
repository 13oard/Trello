package com.sparta.trello.domain.auth.controller;

import com.sparta.trello.domain.auth.dto.request.LoginRequestDto;
import com.sparta.trello.domain.auth.dto.request.SignupRequestDto;
import com.sparta.trello.domain.auth.dto.response.LoginResponseDto;
import com.sparta.trello.domain.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequestDto signupRequest) {
        authService.signup(signupRequest);
        return ResponseEntity.ok("회원가입 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(@RequestBody LoginRequestDto loginRequest) {
        LoginResponseDto response = authService.login(loginRequest);

        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + response.getAccessToken());
        headers.add("Refresh-Token", "Bearer " + response.getRefreshToken());

        return ResponseEntity.ok()
                .headers(headers)
                .body(response);
    }

    @PatchMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        // Authorization 헤더에서 액세스 토큰 추출
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7); // "Bearer "를 제거

            // 서비스 호출
            authService.logout(accessToken);
            return ResponseEntity.ok("로그아웃 성공했습니다.");
        }
        return ResponseEntity.badRequest().body("유효하지 않은 토큰입니다.");
    }

    @PatchMapping("/withdraw")
    public ResponseEntity<String> withdraw(HttpServletRequest request){

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String accessToken = authHeader.substring(7); // "Bearer "를 제거

            // 서비스 호출
            authService.withdraw(accessToken);
            return ResponseEntity.ok("회원 탈퇴되었습니다.");
        }
        return ResponseEntity.badRequest().body("유효하지 않은 토큰입니다.");
    }

}
