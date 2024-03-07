package image.upload.uploadtest.dto.cart;

import com.querydsl.core.annotations.QueryProjection;
import image.upload.uploadtest.entity.Cart;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GetCartDto {

    private Long cartId;
    private String itemName;
    private int price;
    private int quantity;
    private int total_price;

    public GetCartDto() {
    }

    @QueryProjection
    public GetCartDto(Long cartId, String itemName, int price, int quantity, int total_price) {
        this.cartId = cartId;
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.total_price = total_price;
    }

    public GetCartDto(Cart cart) {
        this.cartId = cart.getId();
        this.itemName = cart.getItem().getItemName();
        this.price = cart.getItem().getPrice();
        this.quantity = cart.getQuantity();
        this.total_price = cart.getTotal_price();
    }
}
