package image.upload.uploadtest.dto.order;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CancelOrderResponse {

    private Long orderId;
    private String message;

    public CancelOrderResponse(String message) {
        this.message = message;
    }

    public CancelOrderResponse(Long orderId, String message) {
        this.orderId = orderId;
        this.message = message;
    }
}
