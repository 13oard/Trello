package com.sparta.trello.domain.auth.dto.request;

import lombok.Getter;

@Getter
public class SignupRequestDto {
    private String email;         // 이메일
    private String password;      // 비밀번호
    private String username;      // 이름
}