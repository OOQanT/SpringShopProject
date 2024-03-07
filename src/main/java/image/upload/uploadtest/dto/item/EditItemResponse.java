package image.upload.uploadtest.dto.item;

import image.upload.uploadtest.entity.Item;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EditItemResponse {

    private Long id;
    private String itemName;
    private String price;
    private String quantity;
    private String description;
    private String message;

    public EditItemResponse() {
    }

    public EditItemResponse(Long id, String itemName, String price, String quantity, String message) {
        this.id = id;
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.message = message;
    }

    public EditItemResponse(Item item, String message){
        this.id = item.getId();
        this.itemName = item.getItemName();
        this.price = String.valueOf(item.getPrice());
        this.quantity = String.valueOf(item.getQuantity());
        this.description = item.getDescription();
        this.message = message;
    }

    public EditItemResponse(String message) {
        this.message = message;
    }
}
