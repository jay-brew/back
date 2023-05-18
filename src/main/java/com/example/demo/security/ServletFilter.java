package com.example.demo.security;

import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 예제용 - 실제로 사용하지 않음.
/*
* 서블릿 필터란?
* HttpFilter 또는 Filter 를 상속하는 클래스이다.
* */
public class ServletFilter extends HttpFilter {
    private TokenProvider tokenProvider;

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws IOException, ServletException{
        try {
            final String token = parseBearerToken(request);

            if(token != null && !token.equalsIgnoreCase("null")){
                // userId 가져오기. 위조된 경우 예외 처리된다.
                // Bearer 토큰을 가져와 TokenProvider 를 이용해 사용자를 인증했다.
                String userId = tokenProvider.validateAndGetUserId(token);
                
                // 인증이 완료되면 -> 다음 ServletFilter 실행
                // HttpFilter 클래스를 상속해 doFilter 라는 메서드를 원하는 대로 오버라이딩 해준다.
                filterChain.doFilter(request, response);
            }
        } catch (Exception e) {
            // 인증이 완료되지 않았으면 -> exception 발생
            // 예외 발생 시 response를 403 Forbidden으로 설정. (디스패쳐 서블릿을 실행하지 않고 return)
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        }
    }

    private String parseBearerToken(HttpServletRequest request){
        // Http 요청의 헤더를 파싱해 Bearer 토큰을 리턴한다.
        String bearerToken = request.getHeader("Authorization");

        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    // 이렇게 필터를 구현하고 나면 서블릿 컨테이너(ex. 톰캣)가 ExampleServletFilter 를 사용하도록 어딘가에 설정해야 한다.
    // 어쨌든 스프링 부트를 사용하지 않는 웹 서비스의 경우 web.xml과 같은 설정 파일에 이 필터를 어느 경로에 적용해야 하는지 알려줘야 한다.
    // 그러면 서블릿 컨테이너가 서블릿 필터 실행 시 xml에 설정된 필터를 실행시켜준다.

    // 서블릿 필터가 꼭 한 개일 필요는 없다.
    // 걸러내고 싶은 모든 것을 하나의 클래스에 담으면 크기가 어마어마해질 것이다.
    // 그래서 우리는 기능에 따라 다른 서블릿 필터를 작성할 수 있고 이 서블릿 필터들을 FilterChain을 이용해 연쇄적(chained)으로 순서대로 실행할 수 있다.

    // ex) 검증을 마친 후 부른 메서드
    // filterChain.doFilter(request, response);

    // 그러면 이 서블릿 필터에서 스프링 시큐리티의 위치와 우리가 구현할 필터의 위치는?
    // 스프링 시큐리티 프로젝트를 추가하면 스프링 시큐리티가 FilterChainProxy라는 필터를 서블릿 필터에 끼워 넣어준다.
    // 이 FilterChainProxy 클래스 안에서 내부적으로 필터를 실행시키는데, 이 필터들이 스프링이 관리하는 스프링 빈 필터다(VM Ware)

    // 우리가 상속할 필터는 HttpFilter 가 아닌
    // OncePerRequestFilter 필터이다.
    // web.xml이 아닌
    // WebSecurity ConfigurerAdapter 클래스를 상속해 필터를 설정한다.
}
