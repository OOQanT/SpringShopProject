package image.upload.uploadtest.dto.item;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ItemSearchCondition {
    private String itemName;

    public ItemSearchCondition(String itemName) {
        this.itemName = itemName;
    }
}
