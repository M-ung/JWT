package com.example.jwt.config;

import com.example.jwt.config.jwt.JwtAuthenticationFilter;
import com.example.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
@RequiredArgsConstructor
public class SecurityConfig {
    private final CorsConfig corsConfig;
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    SecurityFilterChain configure(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
        return http
                .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
                .csrf(CsrfConfigurer::disable)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다.
                )
                .addFilter(corsConfig.corsFilter()) // @CrossOrigin(인증x), 시큐리티 필터에 등록 인증(o)
                .formLogin(login -> login
                        .disable()
                )
                .httpBasic(basic -> basic
                        .disable() // basic 방식은 id와 pw를 보내기 떄문에 노출이 될 가능성이 크다. 그래서 bearer token 방법을 쓴다.
                )
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                .authorizeRequests(authorize -> authorize
                        .requestMatchers("/api/v1/user/**")
                        .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .requestMatchers("/api/v1/manager/**")
                        .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                        .requestMatchers("/api/v1/admin/**")
                        .access("hasRole('ROLE_ADMIN')")
                        .anyRequest().permitAll())
                .build();
    }
}
