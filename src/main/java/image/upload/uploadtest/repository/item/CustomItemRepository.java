package image.upload.uploadtest.repository.item;

import image.upload.uploadtest.dto.item.GetItemsDto;
import image.upload.uploadtest.entity.Item;


import java.util.List;

public interface CustomItemRepository {
    List<GetItemsDto> findItemsByCondition(String itemName);

    List<Item> findByItemsByCondition(String itemName);
}
