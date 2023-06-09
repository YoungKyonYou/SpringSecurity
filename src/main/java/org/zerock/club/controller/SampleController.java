package org.zerock.club.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.zerock.club.security.dto.ClubAuthMemberDTO;

@Controller
@Slf4j
@RequestMapping("/sample/")
public class SampleController {
    @PreAuthorize("permitAll()")
    @GetMapping("/all")
    public void exAll(){
        log.info("exAll........");
    }

    @GetMapping("/member")
    //AuthenticationPrincipal 타입은 getPrincipa() 메서드를 통해서 Object 타입의 반환 타입이 있다.
    // 이 코드에 @AuthenticationPrincipal은 별도의 캐스팅 작업 없이 직접 실제
    //ClubAuthMemberDTO 타입을 사용할 수 있기 때문에 좀 더 편하게 사용할 수 있다.
    public void exMember(@AuthenticationPrincipal ClubAuthMemberDTO clubAuthMember){
        log.info("exMember........");

        log.info("----------------------------");
        log.info("{}",clubAuthMember);
    }

//    @GetMapping("/admin")
//    public void exAdmin() {
//        log.info("exAdmin.......");
//    }

//    @PreAuthorize("#clubAuthMember != null && #clubAuthMember.username eq \"user95@zerock.org\"")
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String exMemberOnly(@AuthenticationPrincipal ClubAuthMemberDTO clubAuthMember){
        log.info("exMemberOnly.....");
        log.info("{}",clubAuthMember);

        return "/sample/admin";
    }

}
