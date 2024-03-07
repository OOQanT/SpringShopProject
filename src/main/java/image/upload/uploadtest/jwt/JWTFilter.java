package image.upload.uploadtest.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import image.upload.uploadtest.dto.member.login.CustomUserDetails;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.service.member.LogoutService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;
    private final LogoutService logoutService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String authorization = request.getHeader("Authorization");

        log.info("authorization header = {}",authorization);

        if(authorization == null || !authorization.startsWith("Bearer ")){
            log.info("token null");
            filterChain.doFilter(request,response);

            return;
        }

        String token = authorization.split(" ")[1];

        if(logoutService.isBlacklisted(token)){
            log.info("Blacklisted token detected: {}",token);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            return;
        }

        log.info("token expired={}", jwtUtil.isExpired(token));

        if(jwtUtil.isExpired(token)){
            log.info("token expired");
            filterChain.doFilter(request,response);
            return;
        }

        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        Member member = new Member(username,"tempPassword",role);

        CustomUserDetails customUserDetails = new CustomUserDetails(member);

        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails,null,customUserDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request,response);
    }
}
