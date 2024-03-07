package image.upload.uploadtest.dto.item;

import image.upload.uploadtest.entity.Item;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ItemInfoResponse {

    private Long id;
    private String seller;
    private String itemName;
    private int price;
    private int quantity;
    private String description;
    private List<String> filenames;
    private String message;

    public ItemInfoResponse() {
    }

    public ItemInfoResponse(String message) {
        this.message = message;
    }

    public ItemInfoResponse(Item item) {
        this.id = item.getId();
        this.seller = item.getMember().getNickname();
        this.itemName = item.getItemName();
        this.price = item.getPrice();
        this.quantity = item.getQuantity();
        this.description = item.getDescription();
    }

    public void setFilenames(List<String> filenames){
        this.filenames = filenames;
    }

    public void setMessage(String message){
        this.message = message;
    }
}
