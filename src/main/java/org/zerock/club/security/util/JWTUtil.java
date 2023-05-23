package org.zerock.club.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.util.Date;

@Slf4j
public class JWTUtil {
    private String secretKey = "zerock12345678zerock12345678zerock12345678zerock12345678zerock12345678zerock12345678";

    //1month
    private long expire = 60*24*30;

    /**
     * 주어진 코드에서 Jwts.builder() 및 SignatureAlgorithm.HS256은 최신 버전의 Spring Security에서 deprecated되었습니다. 이러한 변경은 JWT 생성 방식을 개선하기 위해 이루어졌을 수 있습니다.
     */
//    public String generateToken(String content) throws Exception{
//        return Jwts.builder()
//                .setIssuedAt(new Date())
//                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expire).toInstant()))
//                .claim("sub",content)
//                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes("UTF-8"))
//                .compact();
//    }

    public String generateToken(String content) throws Exception {
        byte[] keyBytes = secretKey.getBytes("UTF-8");
        SecretKey key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());
        JwtBuilder builder = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expire).toInstant()))
                .claim("sub", content)
                .signWith(key);

        return builder.compact();
    }

    public String validateAndExtract(String tokenStr) throws Exception {
        String contentValue = null;
        byte[] keyBytes = secretKey.getBytes("UTF-8");
        SecretKey key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());

        try {
            Jws<Claims> jws = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(tokenStr);

            Claims claims = jws.getBody();
            log.info("{}", jws);
            log.info("{}", jws.getBody().getClass());

            log.info("---------------");
            contentValue = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            log.error(e.getMessage());
            contentValue = null;
        }
        return contentValue;
    }
}
