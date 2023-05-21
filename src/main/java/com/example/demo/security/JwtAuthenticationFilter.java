package com.example.demo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter { // OncePerRequestFilter 상속

    @Autowired
    private TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {   // doFilterInternal 오버라이딩
        try {
            // 요청에서 토큰 가져오기.
            String token = parseBearerToken(request);
            log.info("Filter is running...");
            // 토큰 검사하기. JWT 이므로 인가 서버에 요청하지 않고도 검증 가능.
            if (token != null && !token.equalsIgnoreCase("null")) {
                // userID 가져오기. 위조된 경우 예외 처리된다.
                String userId = tokenProvider.validateAndGetUserId(token);
                log.info("Authenticated user ID: " + userId);
                // 인증 완료; SecurityContextHolder 에 등록해야 인증된 사용자라고 생각한다.
                AbstractAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId,    // 인증된 사용자의 정보. 문자열이 아니어도 아무거나 넣을 수 있다. 보통 UserDetails 라는 오브젝트를 넣는데, 우리는 안 만들었음.
                        null,
                        AuthorityUtils.NO_AUTHORITIES
                );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
                securityContext.setAuthentication(authentication);
                SecurityContextHolder.setContext(securityContext);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);
        }

        
        filterChain.doFilter(request, response);
    }

    public String parseBearerToken(HttpServletRequest request) {
        //Http 요청의 헤더를 파싱해 Bearer 토큰을 리턴한다.
        String bearerToken = request.getHeader("Authorization");

        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    /**
     * 1. 요청의 헤더에서 Bearer 토큰을 가져온다. 이 작업은 parseBearerToken() 메서드에서 이뤄진다.
     * 2. TokenProvider 를 이용해 토큰을 인증하고 UsernamePasswordAuthenticationToken 을 작성한다. 이 오브젝트에 사용자의 인증 정보를 저장하고 SecurityContext 에 인증된 사용자를 등록한다.
     * 서버가 요청이 끝나기 전까지 방금 인증한 사용자의 정보를 갖고 있어야 하기 때문이다.
     * 왜 서버가 이와 같은 정보를 가지고 있어야 할까?
     * 요청을 처리하는 과정에서 사용자가 인증됐는지 여부에 인증된 사용자가 누구인지 알아야 할 때가 있기 때문이다.
     */
    
}
