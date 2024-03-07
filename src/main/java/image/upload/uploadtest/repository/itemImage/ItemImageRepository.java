package image.upload.uploadtest.repository.itemImage;

import image.upload.uploadtest.entity.ItemImage;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ItemImageRepository extends JpaRepository<ItemImage,Long> {
    List<ItemImage> findByItemId(Long itemId);
}
