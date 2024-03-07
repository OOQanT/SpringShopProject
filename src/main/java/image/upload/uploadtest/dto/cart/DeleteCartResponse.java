package image.upload.uploadtest.dto.cart;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class DeleteCartResponse {

    private Long cartId;
    private String message;

    public DeleteCartResponse(Long cartId, String message) {
        this.cartId = cartId;
        this.message = message;
    }

    public DeleteCartResponse(String message) {
        this.message = message;
    }
}
