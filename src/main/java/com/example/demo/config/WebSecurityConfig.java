package com.example.demo.config;

import com.example.demo.security.JwtAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Override
    protected  void configure(HttpSecurity http) throws Exception {
        // http 시큐리티 빌더
        http.cors() // WebMvcConfig 에서 이미 설정했으므로 기본 cors 설정
            .and()
            .csrf() // csrf 는 현재 사용하지 않으므로 disable
                .disable()
            .httpBasic()    // 토큰을 사용하므로 basic 인증 disabled
                .disable()
            .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()    // /와 /auth/** 경로는 인증 안 해도 됨.
                .antMatchers("/", "/auth/**").permitAll()
            .anyRequest()   // /와 /auth/** 이외의 모든 경로는 인증해야됨.
                .authenticated();

        // filter 등록.
        // 매 요청마다
        // CorsFilter 실행 후
        // jwtAuthenticationFiler 실행한다.
        http.addFilterAfter(
                jwtAuthenticationFilter,
                CorsFilter.class
                // CorsFilter.class 추가 시 반드시 org.springframework.web.filter.CorsFilter 를 import 해야 한다.
                // 만약 스프링 시큐리티 필터 로그에서 JwtAuthenticationFilter 를 찾을 수 없다면, import 경로를 재확인하라.
        );

        // 마지막 addFilterAfter() 메서드를 실행하는 것은
        // JwtAuthenticationFilter 를 CorsFilter 이후에 실행하라고 설정하는 것이다.
        // CorsFilter 다음에 반드시 실행해야 하는 것은 아니지만,
        // CorsFilter 다음이 적당한 것 같아 그렇게 설정한 것이다.
    }
}
