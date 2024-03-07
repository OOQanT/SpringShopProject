package image.upload.uploadtest.dto.cart;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddItemRequest {

    private Long itemId;
    private int quantity;

    public AddItemRequest() {
    }

    public AddItemRequest(Long itemId, int quantity) {
        this.itemId = itemId;
        this.quantity = quantity;
    }
}
