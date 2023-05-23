package org.zerock.club.security.dto;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

/**
 * ClubAuthMemberDTO를 구성하는 첫 번째 단계는 User 클래스를 상속하고 부모 클래스인 User 클래스의 생성자를 호출할 수 있는 코드를 만드는 것이다.(부모 클래스인 User 클래스에 사용자 정의
 * 생성자가 있으므로 반드시 호출할 필요가 있다.
 * ClubAuthMemberDTO는 DTO 역할을 수행하는 클래스인 동시에 스프링 시큐리티에서 인가/인증 작업에 사용할 수 있습니다.(password는 부모 클래스를 사용하므로 별도의 멤버 변수로 선언하지 않음)\
 * ClubMember가 ClubAuthMemberDTO라는 타입으로 처리된 가장 큰 이유는 사용자의 정보를 가져오는 핵심적인 역할을 하는 UserDetailsService라는 인터페이스 때문이다.
 * 스프링 시큐리티의 구조에서 인증을 담당하는 AuthenticationManager는 내부적으로 UserDetailsService를 호출해서 사용자의 정보를 가져온다.
 * 현재 예제와 같이 JPA로 사용자의 정보를 가져오고 싶다면 이 부분을 UserDetailService가 이용하는 구조로 작성할 필요가 있다.
 * 추가된 service 패키지에는 이를 위한 ClubUserDetailsService 클래스를 다음과 같이 추가한다.
 */
@Slf4j
@Getter
@Setter
@ToString
public class ClubAuthMemberDTO extends User implements OAuth2User {
    private String email;

    private String name;
    private String password;

    private boolean fromSocial;

    private Map<String, Object> attr;
    public ClubAuthMemberDTO(String username, String name, String password, boolean fromSocial, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attr){
        super(username, password, authorities);
        this.email= username;
        this.name= name;
        this.password=password;
        this.fromSocial = fromSocial;
        this.attr=attr;
    }

    public ClubAuthMemberDTO(String username, String name, String password, boolean fromSocial, Collection<? extends GrantedAuthority> authorities){
        super(username, password, authorities);
        this.email= username;
        this.name= name;
        this.password=password;
        this.fromSocial = fromSocial;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attr;
    }
}
