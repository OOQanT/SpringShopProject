package image.upload.uploadtest.dto.cart;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AddItemResponse {

    private Long itemId;
    private int quantity;
    private String message;

    public AddItemResponse() {
    }

    public AddItemResponse(Long itemId, int quantity, String message) {
        this.itemId = itemId;
        this.quantity = quantity;
        this.message = message;
    }

    public AddItemResponse(String message) {
        this.message = message;
    }
}
