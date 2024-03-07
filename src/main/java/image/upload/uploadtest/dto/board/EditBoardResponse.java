package image.upload.uploadtest.dto.board;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Getter
@Setter
public class EditBoardResponse {
    private String title;
    private String nickname;
    private List<String> messages;

    public EditBoardResponse(List<String> messages) {
        this.messages = messages;
    }
    public EditBoardResponse(String title, String nickname, List<String> messages) {
        this.title = title;
        this.nickname = nickname;
        this.messages = messages;
    }
}
