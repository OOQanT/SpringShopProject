package image.upload.uploadtest.dto.comment;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WriteCommentResponse {

    private String comment;
    private String nickname;
    private String message;

    public WriteCommentResponse(String message) {
        this.message = message;
    }

    public WriteCommentResponse(String comment, String nickname, String message) {
        this.comment = comment;
        this.nickname = nickname;
        this.message = message;
    }
}
