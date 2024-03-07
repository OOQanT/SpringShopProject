package image.upload.uploadtest.controller.member;

import image.upload.uploadtest.dto.member.UserInfoDto;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.service.member.MemberService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UserController {

    private final MemberService memberService;
    private final JWTUtil jwtUtil;

    @GetMapping("/user")
    public Result getUser(HttpServletRequest request, HttpServletResponse response){
        String token = request.getHeader("Authorization").split(" ")[1];
        String requestUsername = jwtUtil.getUsername(token);

        try{
            Member member = memberService.findMember(requestUsername);
            UserInfoDto userInfoDto = new UserInfoDto(member.getUsername(), member.getNickname(), member.getEmail(), member.getRole());
            return new Result<>(userInfoDto);

        }catch (NoSuchElementException e){
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return new Result<>("존재하지 않는 유저");
        }
    }

    @Data
    @AllArgsConstructor
    static class Result<T>{
        private T data;
    }
}
