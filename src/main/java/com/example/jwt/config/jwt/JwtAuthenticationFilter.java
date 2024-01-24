package com.example.jwt.config.jwt;

import com.example.jwt.config.auth.PrincipalDetails;
import com.example.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import java.io.IOException;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 가 등장한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    // login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        // 1. username, password 를 받아서
        // 2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하면,
        // PrincipalDetailsService가 호출된다.
        // 그 후 loadUserByUsername이 실행이 된다.

        // 3. PrincipalDetails를 세션에 담고 (권한 관리를 위해서)
        // 4. JWT 토큰을 만들어서 응답하면 됨.
        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
            // 위 방식을 아래 방식으로 간단하게 구현할 수 있다.

            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행된다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken); // 내 로그인 한 정보가 담긴다.

            System.out.println("authentication = " + authentication.getPrincipal());

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // 여기서 오류가 터진다.

            System.out.println("2222222==================================================2222");
            System.out.println("principalDetails = " + principalDetails.getUser().getUsername());

            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
