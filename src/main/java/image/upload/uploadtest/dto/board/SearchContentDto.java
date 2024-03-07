package image.upload.uploadtest.dto.board;

import com.querydsl.core.annotations.QueryProjection;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class SearchContentDto {

    private Long id;
    private String title;
    private String nickname;
    private LocalDateTime createTime;

    public SearchContentDto() {
    }

    @QueryProjection
    public SearchContentDto(Long id, String title, String nickname, LocalDateTime createTime) {
        this.id = id;
        this.title = title;
        this.nickname = nickname;
        this.createTime = createTime;
    }
}
