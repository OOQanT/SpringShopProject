package image.upload.uploadtest.config;

import image.upload.uploadtest.jwt.JWTFilter;
import image.upload.uploadtest.jwt.JWTLogoutHandler;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.jwt.LoginFilter;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.service.member.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final MemberRepository memberRepository;
    private final JWTUtil jwtUtil;
    private final LogoutService logoutService;
    private final JWTLogoutHandler jwtLogoutHandler;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring()
                .requestMatchers(
                        "/resources/**","/static/**","/css/**","/js/**","/images/**","/item/itemimages/**"

                )
                .requestMatchers(PathRequest
                        .toStaticResources()
                        .atCommonLocations()
                );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        http.csrf((csrf) -> csrf.disable());

        http
                .cors((corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Arrays.asList("Authorization","Refresh-Token"));

                        //configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                        //configuration.setExposedHeaders(Collections.singletonList("Refresh-Token"));

                        return configuration;
                    }
                })));

        http
                .formLogin((auth) -> auth.disable());

        http
                .httpBasic((auth) -> auth.disable());

        http
                .authorizeHttpRequests((auth)-> auth
                        .requestMatchers("/","/login","/loginProc","/join/**","/joinProc","/api/**","/token/**","/error","/board/images/**","/item/itemimages/**","/item/getItems/**").permitAll()
                        .anyRequest().authenticated()
                );

        http
                .addFilterBefore(new JWTFilter(jwtUtil,logoutService), LoginFilter.class);

        http
                .addFilterAt(
                        new LoginFilter(authenticationManager(authenticationConfiguration),memberRepository,bCryptPasswordEncoder(),jwtUtil),
                        UsernamePasswordAuthenticationFilter.class
                );

        http
                .logout((auth) -> auth
                        .logoutUrl("/api/logout")
                        .addLogoutHandler(jwtLogoutHandler)
                        .logoutSuccessHandler(((request, response, authentication) -> {
                            response.setStatus(HttpServletResponse.SC_OK);
                        }))
                );


        return http.build();
    }

}
