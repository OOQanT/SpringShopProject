package image.upload.uploadtest.dto.member;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserInfoDto {

    private String username;
    private String nickname;
    private String email;
    private String role;

    public UserInfoDto() {
    }

    public UserInfoDto(String username, String nickname, String email, String role) {
        this.username = username;
        this.nickname = nickname;
        this.email = email;
        this.role = role;
    }
}
