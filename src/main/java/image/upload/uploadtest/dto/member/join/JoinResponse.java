package image.upload.uploadtest.dto.member.join;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class JoinResponse<T> {

    private T data;
    public JoinResponse(T data) {
        this.data = data;
    }
}
