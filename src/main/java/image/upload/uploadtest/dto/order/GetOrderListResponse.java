package image.upload.uploadtest.dto.order;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class GetOrderListResponse {

    private int size;
    private List<GetOrderDto> orderList;
    private String message;

    public GetOrderListResponse(String message) {
        this.message = message;
    }

    public GetOrderListResponse(int size, List<GetOrderDto> orderList, String message) {
        this.size = size;
        this.orderList = orderList;
        this.message = message;
    }
}
