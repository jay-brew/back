package com.example.demo.security;

import com.example.demo.model.UserEntity;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Service
public class TokenProvider {
    private static final String SECRET_KEY = "FLQDRdTrldafSRKDFDFVJvndrkTUDRIENVKndpjtinitTDUIOPnioDRJTtad5kjKL4K3djfVjd4JK5RJ";

    // JWT 라이브러리를 이용해 JWT 토큰을 생성한다.
    public String create(UserEntity userEntity){
        // 기한 지금으로부터 1일로 설정
        Date expiryDate = Date.from(
                Instant.now()
                        .plus(1, ChronoUnit.DAYS));
        /*
        {   // header
            "alg":"HS512"
        }.
        {   // payload
        "sub": "351341d31341c13414t1244",
        "iss": "demo app",
        "iat": 1421315,
        "exp": 1435243,
        }.
        // SECRET_KEY를 이용해 서명한 부분
        N3EKNFNkAEKASDdfDFDATKEJQMPdojeP3O3KAJCODJ13MKFNMCK3OEPDOVNAIEP3kd3FDCI3AIF3Zg
        */
        // JWT Token 생성
        return Jwts.builder()
                // header에 들어갈 내용 및 서명을 하기 위한 SECRET_KEY
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                // payload에 들어갈 내용
                .setSubject(userEntity.getId()) // sub
                .setIssuer("demo app")      // iss
                .setIssuedAt(new Date())    // iat
                .setExpiration(expiryDate)  // exp
                .compact();
    }

    // 토큰을 디코딩, 파싱 및 위조여부를 확인한다. 이후에 우리가 원하는 subject 즉 유저의 아이디를 리턴한다.
    // 라이브러리 덕에 우리가 굳이 JSON을 생성, 서명, 인코딩, 디코딩, 파싱하는 작업을 하지 않아도 된다.
    public String validateAndGetUserId(String token){
        // parseClaimsJws 메서드가 Base 64로 디코딩 및 파싱.
        // 즉, 헤더와 페이로드를 setSigningKey로 넘어온 시크릿을 이용해 서명 후, token의 서명과 비교.
        // 위조되지 않았다면 페이로드(Claims) 리턴, 위조라면 예외를 날림
        // 그 중 우리는 userId가 필요하므로 getBody를 부른다.
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }
}
