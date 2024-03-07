package image.upload.uploadtest.dto.board;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class WriteBoardResponse {
    private String title;
    private String nickname;
    private List<String> messages;

    public WriteBoardResponse(List<String> messages) {
        this.messages = messages;
    }

    public WriteBoardResponse(String title, String nickname, List<String> messages) {
        this.title = title;
        this.nickname = nickname;
        this.messages = messages;
    }
}
