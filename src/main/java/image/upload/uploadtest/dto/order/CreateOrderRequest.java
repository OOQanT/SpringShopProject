package image.upload.uploadtest.dto.order;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class CreateOrderRequest {
    private String address;
    private String detailAddress;
    private String payment;

    public CreateOrderRequest(String address, String detailAddress,String payment) {
        this.address = address;
        this.detailAddress = detailAddress;
        this.payment = payment;
    }
}
