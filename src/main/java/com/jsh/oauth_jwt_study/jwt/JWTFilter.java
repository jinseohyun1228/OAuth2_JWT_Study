package com.jsh.oauth_jwt_study.jwt;

import com.jsh.oauth_jwt_study.dto.CustomOAuth2User;
import com.jsh.oauth_jwt_study.dto.UserDTO;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {
    //강의를 안보고 코드를 짜봐용~!
    private final JWTUtil jwtUtil;

    public JWTFilter(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        /*
        구현 기능:
               1. 요청 쿠키에서 jwt를 꺼내보자.
               2. 없으면 다음 필터 ㄱㄱ
               3. 있으면 jwt 꺼내서 검증하기
         */
        Cookie[] cookies = request.getCookies();
        String token = null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("Authorization")) {
                token = cookie.getValue();
            }
        }

        if (token == null) {
            // 토큰이 없는 경우, 강제 종료를 해야하나?
            System.out.println("토큰이 없어요.");
            filterChain.doFilter(request, response);
            return;
        }

        if (jwtUtil.isExpired(token)) {
            //유효한 검사 실패
            System.out.println("토큰이 만료되었어요.");
            filterChain.doFilter(request, response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserDTO userDTO = new UserDTO();

        userDTO.setRole(role);
        userDTO.setName(username);

        CustomOAuth2User customOAuth2User = new CustomOAuth2User(userDTO);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customOAuth2User, null, customOAuth2User.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        System.out.println(" 올바른 허용이요 ");
        filterChain.doFilter(request, response);
    }
}

