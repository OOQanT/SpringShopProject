package image.upload.uploadtest.dto.board;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SearchCondition {

    private String title;
    private String nickname;

    public SearchCondition() {
    }

    public SearchCondition(String title, String nickname) {
        this.title = title;
        this.nickname = nickname;
    }
}
