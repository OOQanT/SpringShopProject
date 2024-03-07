package image.upload.uploadtest.controller.member;

import image.upload.uploadtest.dto.member.join.JoinRequest;
import image.upload.uploadtest.dto.member.join.JoinResponse;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.service.member.MemberService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequiredArgsConstructor
public class JoinController {

    private final MemberService memberService;
    private final MemberRepository memberRepository;

    @PostMapping("/joinProc")
    public JoinResponse joinMember(@Validated @RequestBody JoinRequest joinRequest, BindingResult bindingResult, HttpServletResponse response){

        if(bindingResult.hasErrors()){
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();
            List<String> collect = fieldErrors.stream().map(m -> m.getDefaultMessage()).collect(Collectors.toList());

            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new JoinResponse<>(collect);
        }

        if(!joinRequest.getPassword().equals(joinRequest.getRePassword())){
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new JoinResponse<>("재입력한 비밀번호가 일치하지 않습니다.");
        }

        boolean result = memberService.joinMember(joinRequest);
        if(!result){
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return new JoinResponse<>("이미 존재하는 아이디나 닉네임");
        }

        return new JoinResponse<>(joinRequest.getUsername());
    }

    @GetMapping("/join/nameChecker")
    public boolean usernameDuplication(@RequestParam(name = "username") String username){
        return memberRepository.existsByUsername(username);
    }

    @GetMapping("/join/nicknameChecker")
    public boolean nicknameDuplication(@RequestParam(name = "nickname") String nickname){
        return memberRepository.existsByNickname(nickname);
    }
}
