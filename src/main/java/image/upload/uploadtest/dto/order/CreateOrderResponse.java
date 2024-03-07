package image.upload.uploadtest.dto.order;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateOrderResponse {

    private Long orderId;
    private String message;

    public CreateOrderResponse(String message) {
        this.message = message;
    }

    public CreateOrderResponse(Long orderId, String message) {
        this.orderId = orderId;
        this.message = message;
    }
}
