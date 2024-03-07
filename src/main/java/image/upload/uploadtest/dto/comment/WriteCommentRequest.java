package image.upload.uploadtest.dto.comment;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class WriteCommentRequest {

    @NotEmpty(message = "댓글을 입력해주세요")
    private String comment;

    public WriteCommentRequest() {

    }

    public WriteCommentRequest(String comment) {
        this.comment = comment;
    }
}
