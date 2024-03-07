package image.upload.uploadtest.dto.member.join;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinRequest {

    @NotEmpty(message = "아이디를 입력해주세요.")
    private String username;

    @NotEmpty(message = "비밀번호를 입력해주세요")
    private String password;

    @NotEmpty(message = "비밀번호를 다시 입력해주세요")
    private String rePassword;

    @NotEmpty(message = "닉네임을 입력해주세요")
    private String nickname;

    @NotEmpty(message = "이메일을 입력해주세요")
    @Email(message = "이메일 형식이 아닙니다.")
    private String email;

    public JoinRequest(String username, String password, String rePassword, String nickname, String email) {
        this.username = username;
        this.password = password;
        this.rePassword = rePassword;
        this.nickname = nickname;
        this.email = email;
    }

}
