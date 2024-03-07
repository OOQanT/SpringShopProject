package image.upload.uploadtest.dto.comment;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class GetCommentResponse {

    private List<GetCommentsDto> comments;
    private String message;

    public GetCommentResponse(List<GetCommentsDto> comments, String message) {
        this.comments = comments;
        this.message = message;
    }

    public GetCommentResponse(String message) {
        this.message = message;
    }
}
