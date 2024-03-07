package image.upload.uploadtest.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import image.upload.uploadtest.dto.member.login.CustomUserDetails;
import image.upload.uploadtest.dto.member.login.LoginFailResponse;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.member.MemberRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JWTUtil jwtUtil;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = obtainUsername(request);
        String password = obtainPassword(request);

        Optional<Member> findMember = memberRepository.findByUsername(username);

        if(findMember.isPresent()){
            String findMemberPassword = findMember.get().getPassword();
            if(!bCryptPasswordEncoder.matches(password,findMemberPassword)){
                log.info("password = {}", password);
                log.info("findMemberPassword = {}",findMemberPassword);
                log.info("passwordEncode = {}", bCryptPasswordEncoder.encode(password));

                try{
                    response.setContentType("application/json");
                    response.setCharacterEncoding("UTF-8");
                    response.getWriter().write(objectMapper.writeValueAsString(new LoginFailResponse("아이디나 비밀번호를 확인해주세요")));
                    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    response.getWriter().flush();
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password,null);

        return authenticationManager.authenticate(authToken);

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        CustomUserDetails customUserDetails = (CustomUserDetails) authResult.getPrincipal();
        String username = customUserDetails.getUsername();

        Collection<? extends GrantedAuthority> authorities = customUserDetails.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority();

        String token = jwtUtil.createJwt(username, role, 30 * 60 * 1000L);

        response.setHeader("Authorization", "Bearer " + token);

        log.info("==================================Login Success==================================");
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(401);
        log.info("fail LoginFilter");
    }
}
