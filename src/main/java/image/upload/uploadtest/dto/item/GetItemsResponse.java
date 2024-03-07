package image.upload.uploadtest.dto.item;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class GetItemsResponse {

    private List<GetItemsDto> items;
    private String message;

    public GetItemsResponse(String message) {
        this.message = message;
    }

    public GetItemsResponse(List<GetItemsDto> items, String message) {
        this.items = items;
        this.message = message;
    }
}
