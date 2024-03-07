package image.upload.uploadtest.dto.order;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
public class GetOrderDto {

    private Long orderId;
    private int totalPrice;
    private LocalDateTime orderTime;
    private String delivery;
    private String payment;
    private String orderState;

    public GetOrderDto() {
    }

    public GetOrderDto(Long orderId, int totalPrice, LocalDateTime orderTime, String delivery,String payment) {
        this.orderId = orderId;
        this.totalPrice = totalPrice;
        this.orderTime = orderTime;
        this.delivery = delivery;
        this.payment = payment;
    }
}
