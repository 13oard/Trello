package com.sparta.trello.domain.auth.service;

import com.sparta.trello.domain.auth.dto.request.LoginRequestDto;
import com.sparta.trello.domain.auth.dto.request.SignupRequestDto;
import com.sparta.trello.domain.auth.dto.response.LoginResponseDto;
import com.sparta.trello.domain.user.entity.User;

import java.util.UUID;

public interface AuthService {
    // 사용자 정보 업데이트
    User update(UUID userId, String newEmail, String newUserId);

    // 회원가입
    void signup(SignupRequestDto signupRequest);

    // 로그인
    LoginResponseDto login(LoginRequestDto loginRequest);

    //로그아웃
    void logout(String accessToken);

    //회원탈퇴
    void withdraw(String accessToken);

    User getUser();

}