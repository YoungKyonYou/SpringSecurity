package org.zerock.club.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.zerock.club.handler.ClubLoginSuccessHandler;
import org.zerock.club.security.filter.ApiCheckFilter;
import org.zerock.club.security.filter.ApiLoginFilter;
import org.zerock.club.security.handler.ApiLoginFailHandler;
import org.zerock.club.security.service.ClubOAuth2UserDetailsService;
import org.zerock.club.security.service.ClubUserDetailsService;
import org.zerock.club.security.util.JWTUtil;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * SecurityConfig 클래스는 시큐리티 관련 기능을 쉽게 설정하기 위해서 WebSecurityConfigurerAdapter라는 클래스를 상속으로 처리한다.
 * WebSecurityConfigurerAdapter 클래스는 주로 override를 통해서 여러 설정을 조정하게 된다.
 * 하지만 이는 Deprecated 됐음으로 이제는 SecurityFilterChain를 빈으로 등록해서 사용하는 것을 권장한다.
 */
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@Configuration
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final ClubUserDetailsService detailsService;
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * configure 메서드를 Override 하는 대신 이렇게 사용
     *
     * inMemoryUserDetailsManager 객체를 생성해서 한 명의 사용자를 생성한다 권한에는 'USER'라는 권한을 지정한다.
     * User.withDefaultPasswordEncoder() 쓰는 것 또한 deprecated 되어 아래 처럼 사용한다
     */
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user1")
//                .password("$2a$10$z9PR8QnyQ5c.FJA2kVwuIONAHbY5oU20dct7FdvmJ93ztR7bSPRFK")
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

    /**
     * ClubUserDetailsService.java에서 이를 구현해주고 있다.
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails user = User.builder()
//                .username("user1")
//                .password(passwordEncoder().encode("1111"))
//                .roles("USER")
//                .build();
//        return new InMemoryUserDetailsManager(user);
//    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /**
         * 이제 Config 파일에서 AbstractAuthenticationProcessingFilter를 사용하기 위해선 authenticationManager가 필요한데,
         * 스프링 3.0 이전에는 WebSecurityConfigurationAdapater에 authenticationManger 변수를 사용하는 것으로 가능했다.
         * 하지만, 스프링 3.0 이후, 해당 클래스가 deprecated 되었기에, 3.0 이후의 버전 사용자는 이제 아래와 같이 Builder를 통해
         * Build해주어야한다.
         */
        //AuthenticationManager 설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(detailsService).passwordEncoder(passwordEncoder());

        //Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        //반드시 필요
        http.authenticationManager(authenticationManager);


        //sample/all 로 접속하면 로그인 절차 없이 접속가능
        //sample/member로 접속하면 에러 페이지가 뜨게 된다.
        //여기서 formLogin()이라는 기능은 이와 같이 인가/인증 절차에서 문제가 발생했을 때 로그인 페이지를 보여주도록 지정할 수 있다.

        /**
         *  잠깐 admin만 접속할 수 있게 변경,. 그래서 주석처리함
         */
//        http.authorizeHttpRequests()
//                .antMatchers("/sample/all").permitAll()
//                .antMatchers("/sample/member").hasRole("USER");
        http.formLogin();
        //이 프로젝트는 외부에서 REST 방식으로 이용할 수 있는 보안 설정을 다루기 위해서 CSRF 토큰을 발행하지 않는 방식으로 설정하고 진행한다.
        http.csrf().disable();
        //로그아웃 처리, 여기서 주의해야 할 점은 CSRF 토큰을 사용할 때는 반드시 POST 방식으로만 로그아웃을 처리 해야 한다
        //CSRF 토큰을 이용하는 경우에는 '/logout'이라는 URL을 호출했을 때 <form> 태그와 버튼으로 구성된 화면을 보게 된다.
        //반면에 CSRF 토큰을 disable()로 비활성화 시키면 GET 방식('/logout')로 비활성화 시키면 GET 방식('/logout')으로도 로그아웃이 처리된다.
        http.oauth2Login().successHandler(successHandler());
        //소셜 로그인은 rememberMe 사용 불가
        http.rememberMe().tokenValiditySeconds(60*60*7).userDetailsService(detailsService);

        http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(apiLoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public ClubLoginSuccessHandler successHandler(){
        return new ClubLoginSuccessHandler(passwordEncoder());
    }

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
//        http
//                .authorizeHttpRequests((authz)->authz
//                        .anyRequest().authenticated()
//                )
//                .httpBasic(withDefaults());
//        return http.build();
//    }

    @Bean
    public ApiCheckFilter apiCheckFilter(){
        return new ApiCheckFilter("/notes/**/*", jwtUtil());
    }


    public ApiLoginFilter apiLoginFilter(AuthenticationManager authenticationManager){
        ApiLoginFilter apiLoginFilter = new ApiLoginFilter("/api/login", jwtUtil());
        apiLoginFilter.setAuthenticationManager(authenticationManager);

        //ApiLoginFailHandler는 AuthenticationFailureHandler 인터페이스를 구현하는 클래스로 오직 인증에 실패하는 경우에 처리를 전담하도록 한다
        //인증에 실패하면 401 상태 코드를 반환하도록 한다
        apiLoginFilter.setAuthenticationFailureHandler(new ApiLoginFailHandler());
        return apiLoginFilter;
    }

    @Bean
    public JWTUtil jwtUtil(){
        return new JWTUtil();
    }
}
