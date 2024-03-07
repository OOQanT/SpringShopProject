package image.upload.uploadtest.service.item;

import image.upload.uploadtest.dto.item.EditItemRequest;
import image.upload.uploadtest.dto.item.GetItemsDto;
import image.upload.uploadtest.dto.item.ItemInfoResponse;
import image.upload.uploadtest.dto.item.ItemRegisterRequest;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.entity.ItemImage;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.item.ItemRepository;
import image.upload.uploadtest.repository.itemImage.ItemImageRepository;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.service.itemImage.ItemImageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ItemService {

    private final ItemRepository itemRepository;
    private final MemberRepository memberRepository;
    private final ItemImageRepository itemImageRepository;
    private final ItemImageService itemImageService;

    @Transactional
    public Item save(String requestUsername, ItemRegisterRequest itemRegisterRequest){
        Member findMember = memberRepository.findByUsername(requestUsername)
                .orElseThrow(() -> new NoSuchElementException("존재하지않는 회원입니다."));

        Item item = new Item(itemRegisterRequest);
        item.setMember(findMember);

        if(itemRegisterRequest.getImageFiles() == null || itemRegisterRequest.getImageFiles().isEmpty()){
            item.setIsFile(false);
        }else{
            item.setIsFile(true);
        }

        itemRepository.save(item);

        return item;
    }

    public List<GetItemsDto> getItems(){
        List<Item> all = itemRepository.findAll();

        if(all == null || all.isEmpty()){
            throw new NoSuchElementException("아이템이 존재하지 않습니다.");
        }

        List<GetItemsDto> items = new ArrayList<>();

        for (Item item : all) {
            GetItemsDto getItemsDto = new GetItemsDto(item);
            if(item.isFile()){
                List<ItemImage> findImages = itemImageRepository.findByItemId(item.getId());
                List<String> filenames = new ArrayList<>();
                if(findImages == null || findImages.isEmpty()){
                    throw new NoSuchElementException("이미지가 존재하지 않습니다.");
                }

                for (ItemImage findImage : findImages) {
                    filenames.add(findImage.getStoreFilename());
                }
                getItemsDto.setImages(filenames);
            }
            items.add(getItemsDto);
        }

        return items;
    }

    public List<GetItemsDto> getItemsByCondition(String itemName){
        List<Item> findItems = itemRepository.findByItemsByCondition(itemName);

        if(findItems.isEmpty()){
            throw new NoSuchElementException("상품이 존재하지 않습니다.");
        }

        List<GetItemsDto> items = new ArrayList<>();
        for (Item findItem : findItems) {
            GetItemsDto getItemsDto = new GetItemsDto(findItem);
            if(findItem.isFile()){
                List<ItemImage> findImages = itemImageRepository.findByItemId(findItem.getId());
                List<String> filenames = findImages.stream().map(ItemImage::getStoreFilename).toList();
                getItemsDto.setImages(filenames);
            }
            items.add(getItemsDto);
        }
        
        return items;
    }

    public ItemInfoResponse findItem(Long itemId){
        Item findItem = itemRepository.findById(itemId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 상품"));

        ItemInfoResponse itemInfoResponse = new ItemInfoResponse(findItem);

        if(findItem.isFile()){
            List<ItemImage> findImages = itemImageRepository.findByItemId(itemId);
            if(findImages.isEmpty()){
                throw new NoSuchElementException("존재하지 않는 이미지");
            }

            List<String> collect = findImages.stream().map(ItemImage::getStoreFilename).toList();
            itemInfoResponse.setFilenames(collect);
        }

        return itemInfoResponse;
    }

    @Transactional
    public Item edit(Long itemId, String requestUsername, EditItemRequest editItemRequest) throws IOException {
        Item findItem = itemRepository.findById(itemId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 아이템 입니다."));

        if(!findItem.getMember().getUsername().equals(requestUsername)){
            throw new IllegalArgumentException("타인의 상품은 수정할 수 없습니다.");
        }

        findItem.setItemName(editItemRequest.getItemName());
        findItem.setPrice(editItemRequest.getPrice());
        findItem.setQuantity(editItemRequest.getQuantity());
        findItem.setDescription(editItemRequest.getDescription());

        if (editItemRequest.getItemImages() == null || editItemRequest.getItemImages().isEmpty()){
            itemImageService.delete(findItem.getId());
            findItem.setIsFile(false);
            return findItem;
        }

        itemImageService.edit(itemId,editItemRequest.getItemImages(),findItem);
        findItem.setIsFile(true);

        return findItem;
    }


    @Transactional
    public boolean delete(Long itemId, String requestUsername){
        Item findItem = itemRepository.findById(itemId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 상품입니다."));

        if(!findItem.getMember().getUsername().equals(requestUsername)){
            throw new IllegalArgumentException("타인의 상품은 삭제할 수 없습니다.");
        }

        if(findItem.isFile()){
            itemImageService.delete(itemId);
        }

        itemRepository.delete(findItem);
        return true;
    }
}
