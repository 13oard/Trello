package com.sparta.trello.domain.auth.service;


import com.sparta.trello.domain.auth.dto.request.LoginRequestDto;
import com.sparta.trello.domain.auth.dto.request.SignupRequestDto;
import com.sparta.trello.domain.auth.dto.response.LoginResponseDto;
import com.sparta.trello.domain.auth.entity.Auth;
import com.sparta.trello.domain.auth.exception.UnauthorizedException;
import com.sparta.trello.domain.auth.repository.AuthRepository;
import com.sparta.trello.domain.auth.util.JwtUtil;
import com.sparta.trello.domain.user.entity.User;
import com.sparta.trello.domain.user.entity.UserStatus;
import com.sparta.trello.domain.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthRepository authRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @Override
    public User update(UUID userId, String newEmail, String newUserId) {
        return null;
    }

    @Override
    public void signup(SignupRequestDto signupRequest) {
        String encodedPassword = passwordEncoder.encode(signupRequest.getPassword());
        Auth auth = Auth.builder()
                .email(signupRequest.getEmail())
                .name(signupRequest.getUsername())
                .password(encodedPassword)
                .build();
        authRepository.save(auth);

        User user = User.builder()
                .email(signupRequest.getEmail())
                .name(signupRequest.getUsername())
                .auth(auth)
                .userStatus(UserStatus.ACTIVE)
                .build();
        userService.save(user);
    }

    @Override
    public LoginResponseDto login(LoginRequestDto loginRequest) {
        Optional<Auth> authOptional = authRepository.findByEmail(loginRequest.getEmail());
        if (authOptional.isEmpty() ||
                !passwordEncoder.matches(loginRequest.getPassword(),
                        authOptional.get().getPassword())) {
            throw new UnauthorizedException("회원 정보를 찾을수 없습니다.");
        }

        Auth auth = authOptional.get();
        String token = jwtUtil.createRefreshToken(auth.getName());
        String refreshToken = jwtUtil.createRefreshToken(auth.getName());

        User user = auth.getUser();
        user.updateRefreshToken(refreshToken);
        userService.save(user);

        return new LoginResponseDto(token, refreshToken);
    }

    // 유저 찾기
    @Override
    public User getUser() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        Optional<Auth> authOptional = authRepository.findByName(username);
        return authOptional.map(Auth::getUser)
                .orElseThrow(() -> new UnauthorizedException("사용자를 찾을 수 없습니다."));
    }
}
