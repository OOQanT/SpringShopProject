package image.upload.uploadtest.dto.board;

import lombok.Getter;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;


@Getter
@Setter
public class SearchContentResponse {

    private List<SearchContentDto> data;
    private String message;

    public SearchContentResponse(String message) {
        this.message = message;
    }

    public SearchContentResponse(List<SearchContentDto> data, String message) {
        this.data = data;
        this.message = message;
    }
}
