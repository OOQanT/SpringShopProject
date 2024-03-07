package image.upload.uploadtest.dto.item;

import image.upload.uploadtest.entity.Item;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class ItemRegisterResponse {

    private String itemName;
    private String price;
    private String quantity;
    private String description;
    private String message;

    public ItemRegisterResponse() {
    }

    public ItemRegisterResponse(String itemName, String price, String quantity, String description,String message) {
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.description = description;
        this.message = message;
    }

    public ItemRegisterResponse(Item item, String message){
        this.itemName = item.getItemName();
        this.price = String.valueOf(item.getPrice());
        this.quantity = String.valueOf(item.getQuantity());
        this.description = item.getDescription();
        this.message = message;
    }

    public ItemRegisterResponse(String message) {
        this.message = message;
    }
}
