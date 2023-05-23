package org.zerock.club.security.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JWTUtilTest {

    private JWTUtil jwtUtil;

    @BeforeEach
    public void testBefore(){
        System.out.println("testBefore...............");
        jwtUtil = new JWTUtil();
    }

    @Test
    public void testEncode() throws Exception{
        String email = "user95@zerock.org";

        String str = jwtUtil.generateToken(email);
        System.out.println(str);
    }

    @Test
    public void testValidate() throws Exception{
        String email = "user95@zerock.org";
        String str = jwtUtil.generateToken(email);
        Thread.sleep(5000);
        System.out.println("str 값:"+str);
        String resultEmail = jwtUtil.validateAndExtract(str);
        System.out.println(resultEmail);
    }

}