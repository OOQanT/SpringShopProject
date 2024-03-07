package image.upload.uploadtest.service.itemImage;

import image.upload.uploadtest.dto.item.ItemRegisterRequest;
import image.upload.uploadtest.entity.ImageFiles;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.entity.ItemImage;
import image.upload.uploadtest.repository.itemImage.ItemImageRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ItemImageService {

    @Value("${file.item.dir}")
    private String fileDir;

    private final ItemImageRepository itemImageRepository;

    public void save(Item item, List<MultipartFile> itemImages) throws IOException {

        for (MultipartFile imageFile : itemImages) {
            ItemImage itemImage = new ItemImage(imageFile.getOriginalFilename());
            itemImage.createStoreFileName();
            itemImage.setItem(item);

            imageFile.transferTo(new File(fileDir + itemImage.getStoreFilename()));
            itemImageRepository.save(itemImage);
        }
    }

    public void edit(Long itemId, List<MultipartFile> itemImages, Item item) throws IOException {
        List<ItemImage> findImages = itemImageRepository.findByItemId(itemId);
        if(!findImages.isEmpty()){
            for (ItemImage findImage : findImages) {
                File file = new File(fileDir + findImage.getStoreFilename());
                boolean delete = file.delete();
                if(!delete){
                    throw new IllegalArgumentException("파일 삭제 중 문제발생");
                }
                itemImageRepository.delete(findImage);
            }
        }

        for (MultipartFile itemImage : itemImages) {
            ItemImage image = new ItemImage(itemImage.getOriginalFilename());
            image.createStoreFileName();
            image.setItem(item);

            itemImage.transferTo(new File(fileDir + image.getStoreFilename()));
            itemImageRepository.save(image);
        }
    }

    public void delete(Long itemId){
        List<ItemImage> findImages = itemImageRepository.findByItemId(itemId);
        if(findImages.isEmpty()){
            throw new NoSuchElementException("이미지가 존재하지 않습니다.");
        }

        for (ItemImage findImage : findImages) {
            File file = new File(fileDir + findImage.getStoreFilename());
            boolean delete = file.delete();
            if(!delete){
                throw new IllegalArgumentException("파일 삭제 중 문제발생");
            }
            itemImageRepository.delete(findImage);
        }
    }
}
