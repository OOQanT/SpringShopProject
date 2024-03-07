package image.upload.uploadtest.dto.board;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteBoardResponse {
    private String message;

    public DeleteBoardResponse(String message) {
        this.message = message;
    }
}
