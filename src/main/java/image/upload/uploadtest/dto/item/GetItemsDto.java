package image.upload.uploadtest.dto.item;

import com.querydsl.core.annotations.QueryProjection;
import image.upload.uploadtest.entity.Item;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Setter
@Getter
public class GetItemsDto {

    private Long id;
    private String seller;
    private String itemName;
    private int price;
    private int quantity;
    private boolean isFile;
    private List<String> storeFilename;


    public GetItemsDto() {
    }

    public GetItemsDto(Item item) {
        this.id = item.getId();
        this.seller = item.getMember().getNickname();
        this.itemName = item.getItemName();
        this.price = item.getPrice();
        this.quantity = item.getQuantity();
        this.isFile = item.isFile();
    }

    @QueryProjection
    public GetItemsDto(Long id, String seller, String itemName, int price, int quantity,boolean isFile) {
        this.id = id;
        this.seller = seller;
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.isFile = isFile;
    }

    public void setImages(List<String> storeFilename){
        this.storeFilename = storeFilename;
    }

}
