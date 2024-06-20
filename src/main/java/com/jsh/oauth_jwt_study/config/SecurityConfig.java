package com.jsh.oauth_jwt_study.config;

import com.jsh.oauth_jwt_study.jwt.JWTUtil;
import com.jsh.oauth_jwt_study.oauth2.CustomSuccessHandler;
import com.jsh.oauth_jwt_study.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final JWTUtil jwtUtil;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService, CustomSuccessHandler customSuccessHandler, JWTUtil jwtUtil) {
        this.customOAuth2UserService = customOAuth2UserService;
        this.customSuccessHandler = customSuccessHandler;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                //csrf disable
                .csrf((auth) -> auth.disable())

                //From 로그인 방식 disable
                .formLogin((auth) -> auth.disable())

                //HTTP Basic 인증 방식 disable
                .httpBasic((auth) -> auth.disable())

                //oauth2 (예전 버전 : .oauth2Login(Customizer.withDefaults())
                .oauth2Login((oauth2) -> oauth2
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserService))
                        .successHandler(customSuccessHandler)) // 성공 후 핸들러 추가

                //경로별 인가 작업
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/").permitAll()
                        .anyRequest().authenticated())

                //세션 설정 : STATELESS
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}
