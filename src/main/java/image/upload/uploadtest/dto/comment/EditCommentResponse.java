package image.upload.uploadtest.dto.comment;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EditCommentResponse {
    private String comment;
    private String nickname;
    private String message;

    public EditCommentResponse(String message) {
        this.message = message;
    }

    public EditCommentResponse(String comment, String nickname, String message) {
        this.comment = comment;
        this.nickname = nickname;
        this.message = message;
    }
}
