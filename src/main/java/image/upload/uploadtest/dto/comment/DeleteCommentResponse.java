package image.upload.uploadtest.dto.comment;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteCommentResponse {

    private String message;

    public DeleteCommentResponse(String message) {
        this.message = message;
    }
}
