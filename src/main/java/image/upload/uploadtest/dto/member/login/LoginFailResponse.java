package image.upload.uploadtest.dto.member.login;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginFailResponse {

    private String message;

    public LoginFailResponse() {
    }

    public LoginFailResponse(String message) {
        this.message = message;
    }
}
