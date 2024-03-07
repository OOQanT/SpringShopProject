package image.upload.uploadtest.repository.item;

import image.upload.uploadtest.entity.Item;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemRepository extends JpaRepository<Item,Long>, CustomItemRepository {
}
