package image.upload.uploadtest.dto.cart;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class GetCartResponse {

    private List<GetCartDto> cartList;
    private String message;

    public GetCartResponse() {
    }

    public GetCartResponse(String message) {
        this.message = message;
    }

    public GetCartResponse(List<GetCartDto> cartList, String message) {
        this.cartList = cartList;
        this.message = message;
    }
}
