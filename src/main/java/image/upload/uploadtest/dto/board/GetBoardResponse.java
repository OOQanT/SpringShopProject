package image.upload.uploadtest.dto.board;

import image.upload.uploadtest.entity.Board;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
public class GetBoardResponse {

    private Long id;
    private String title;
    private String content;
    private String nickname;
    private LocalDateTime createTime;
    private List<String> filenames;
    private String message;

    public GetBoardResponse(String message) {
        this.message = message;
    }

    public GetBoardResponse(Board board, String message) {
        this.id = board.getId();
        this.title = board.getTitle();
        this.content = board.getContent();
        this.nickname = board.getMember().getNickname();
        this.createTime = board.getCreateTime();
        this.message = message;
    }

    public GetBoardResponse(Board board, List<String> filenames, String message) {
        this.id = board.getId();
        this.title = board.getTitle();
        this.content = board.getContent();
        this.nickname = board.getMember().getNickname();
        this.createTime = board.getCreateTime();
        this.filenames = filenames;
        this.message = message;
    }

}
