package image.upload.uploadtest.dto.comment;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class GetCommentsDto {

    private Long id;
    private String comment;
    private String nickname;
    private LocalDateTime createTime;

    public GetCommentsDto() {
    }

    public GetCommentsDto(Long id,String comment, String nickname, LocalDateTime createTime) {
        this.id = id;
        this.comment = comment;
        this.nickname = nickname;
        this.createTime = createTime;
    }
}
