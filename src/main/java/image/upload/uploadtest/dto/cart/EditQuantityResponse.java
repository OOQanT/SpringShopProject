package image.upload.uploadtest.dto.cart;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EditQuantityResponse {

    private Long itemId;
    private int quantity;
    private String message;
    public EditQuantityResponse(Long itemId, int quantity, String message) {
        this.itemId = itemId;
        this.quantity = quantity;
        this.message = message;
    }
    public EditQuantityResponse(String message) {
        this.message = message;
    }
}
