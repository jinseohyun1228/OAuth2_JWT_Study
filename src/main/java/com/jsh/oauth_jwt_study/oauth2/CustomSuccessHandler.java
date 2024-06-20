package com.jsh.oauth_jwt_study.oauth2;

import com.jsh.oauth_jwt_study.dto.CustomOAuth2User;
import com.jsh.oauth_jwt_study.jwt.JWTUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JWTUtil jwtUtil;

    public CustomSuccessHandler(JWTUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    /*
    * 스프링 시큐리티에서 인증이 성공적으로 완료된 후 수행되는 작업을 정의한다.
    * 이 메서드가 수행할 수 있는 것
    *
    * 1. 리다이렉션 처리
    * 2. 세션관리
    * 3. 쿠키 설정
    * 4. 로그 기록
    * 5. 추가적인 비즈니스 로직 수행
    *
    * 파라미터 정보
    * HttpServletRequest request:
    * - HTTP 요청 객체
    * - 요청의 헤더, 파라미터, 세션 정보에 접근할 수 있다.
    *
    * HttpServletResponse response:
    * - HTTP 응답 객체, 서버가 클라이언트에게 요청을 보낼 때 사용한다.
    * - 응답의 상태 코드 설정, 헤더 설정, 응답 본문 작성 등을 수행할 수 있습니다.
    *   예를 들어, 리다이렉션을 수행하거나 쿠키를 설정할 수 있습니다.
    *
    * Authentication authentication:
    * - 스프링 시큐리티의 인증 객체로, 사용자가 인증에 성공하면 시큐리티가 관리하게 되는 객체다.
    * - 인증된 사용자의 상세 정보(예: 사용자 이름, 권한, 인증 방식 등)를 접근할 수 있게 한다.
    *
    * 내 프로젝트의 경우  CustomOAuth2UserService의 loadUser 메서드에서 반환되는
    *       CustomOAuth2User 객체가 Authentication 객체에 담긴다.
    */
        //OAuth2User
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();

        //토큰을 만드는 코드
        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 60*60*60L);

        //쿠키를 구워요~! 🍪🍪
        response.addCookie(createCookie("Authorization", token));
        response.sendRedirect("http://localhost:3000/");
    }

    private Cookie createCookie(String authorization, String token) {
        //클래스 이름이 어떻게 쿠키? 너무 귀여워... 🥲
        Cookie cooKie = new Cookie(authorization,token);

        cooKie.setMaxAge(60*60*60); //쿠키가 적용될 유효 시간을 설정한다. (여기서는 60시간..ㄷㄷ)
        cooKie.setPath("/"); //쿠키가 유효한 경로를 설정한다. "/"는 루트 경로로 설정해 모든 경로에서 쿠키가 유효하도록 설정한다.
        cooKie.setHttpOnly(true); // 쿠키를 HTTP(S)에서만 접근 가능하도록 한다.
      //cooKie.setSecure(true); //쿠키를 HTTPS으로만 전송되도록 설정한다. (그런데 나는 돈없어서 HTTP임 그래서 주석할거임ㅋ)

        return cooKie;
        /*
        이 외에도 자주 사용하는 쿠키 클래스 관련 코드를 알아보자.

        <쿠키를 조회하는 코드>
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("name".equals(cookie.getName())) {
                        String value = cookie.getValue();
                        // 쿠키 값 사용
                    }
                }
            }

        <쿠키를 삭제하는 방법>
            cookie.setMaxAge(0); // 유효 기간을 0으로 설정하여 쿠키 삭제

        */
    }
}
