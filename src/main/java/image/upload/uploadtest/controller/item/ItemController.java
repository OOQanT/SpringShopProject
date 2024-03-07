package image.upload.uploadtest.controller.item;

import image.upload.uploadtest.dto.item.*;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.service.item.ItemService;
import image.upload.uploadtest.service.itemImage.ItemImageService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/item")
public class ItemController {

    @Value("${file.item.dir}")
    private String fileDir;

    private final ItemService itemService;
    private final ItemImageService itemImageService;
    private final JWTUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<ItemRegisterResponse> register(HttpServletRequest request,
                                                         @Validated @ModelAttribute ItemRegisterRequest itemRegisterRequest,
                                                         BindingResult bindingResult){

        if(bindingResult.hasErrors()){
            log.info("errors={}",bindingResult.getFieldErrors());
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();

            ItemRegisterResponse res = new ItemRegisterResponse();
            for (FieldError fieldError : fieldErrors) {
                if(fieldError.getCode().equals("typeMismatch")){
                    if(fieldError.getField().equals("price")){
                        res.setPrice("정수를 입력해주세요");
                    }else if (fieldError.getField().equals("quantity")){
                        res.setQuantity("정수를 입력해주세요");
                    }
                }else{
                    if(fieldError.getField().equals("price")){
                        res.setPrice(fieldError.getDefaultMessage());
                    }else if (fieldError.getField().equals("quantity")){
                        res.setQuantity(fieldError.getDefaultMessage());
                    }else{
                        res.setDescription(fieldError.getDefaultMessage());
                    }
                }
            }
            res.setMessage("실패");

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(res);
        }

        String requestUsername = getUsername(request);


        try{
            if(itemRegisterRequest.getImageFiles() == null || itemRegisterRequest.getImageFiles().isEmpty()){
                Item registeredItem = itemService.save(requestUsername, itemRegisterRequest);

                return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                        .body(new ItemRegisterResponse(registeredItem,"성공"));
            }

            Item registeredItem = itemService.save(requestUsername, itemRegisterRequest);
            itemImageService.save(registeredItem,itemRegisterRequest.getImageFiles());

            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new ItemRegisterResponse(registeredItem,"성공"));

        }catch (NoSuchElementException | IOException e){

            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new ItemRegisterResponse(e.getMessage()));
        }

    }

    @GetMapping("/getItems")
    public ResponseEntity<GetItemsResponse> getItems(){
        try{
            List<GetItemsDto> items = itemService.getItems();
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new GetItemsResponse(items,"성공"));
        }catch (NoSuchElementException e){

            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new GetItemsResponse(e.getMessage()));
        }
    }

    @GetMapping("/getItems/search")
    public ResponseEntity<GetItemsResponse> getItemsBySearchCondition(@RequestParam(name = "itemName") String itemName){

        List<GetItemsDto> findItemsByCondition = itemService.getItemsByCondition(itemName);
        try{
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new GetItemsResponse(findItemsByCondition,"성공"));
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new GetItemsResponse(e.getMessage()));
        }

    }

    @GetMapping("/getItems/{itemId}")
    public ResponseEntity<ItemInfoResponse> getItem(@PathVariable Long itemId){

        try{
            ItemInfoResponse findItem = itemService.findItem(itemId);
            findItem.setMessage("성공");
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(findItem);
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new ItemInfoResponse(e.getMessage()));
        }
    }

    @GetMapping("/itemimages/{filename}")
    public ResponseEntity<Resource> downloadExecute(@PathVariable("filename") String filename) throws IOException {
        log.info("Full Path = {}", fileDir + filename);

        String str = URLEncoder.encode(filename, "UTF-8");

        Path path = Paths.get(fileDir + filename);
        Resource resource = new InputStreamResource(java.nio.file.Files.newInputStream(path));
        System.out.println("resource : "+ resource.getFilename());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/octect-stream")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename="+str+";")
                .body(resource);
    }

    @PutMapping("/{itemId}/edit")
    public ResponseEntity<EditItemResponse> edit_item(@PathVariable Long itemId, HttpServletRequest request,
                          @Validated @ModelAttribute EditItemRequest editItemRequest, BindingResult bindingResult){

        EditItemResponse res = new EditItemResponse();

        if(bindingResult.hasErrors()){
            log.info("errors={}",bindingResult.getFieldErrors());

            List<FieldError> fieldErrors = bindingResult.getFieldErrors();
            for (FieldError fieldError : fieldErrors) {
                if(fieldError.getCode().equals("typeMismatch")){
                    if(fieldError.getField().equals("price")){
                        res.setPrice("정수를 입력해주세요");
                    }else{
                        res.setQuantity("정수를 입력해주세요");
                    }
                }else{
                    if(fieldError.getField().equals("price")){
                        res.setPrice(fieldError.getDefaultMessage());
                    }else{
                        res.setQuantity(fieldError.getDefaultMessage());
                    }
                }
            }
            res.setMessage("실패");

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(res);
        }

        String requestUsername = getUsername(request);

        try{
            Item edit = itemService.edit(itemId, requestUsername, editItemRequest);

            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new EditItemResponse(edit, "성공"));
        }catch (NoSuchElementException | IOException | IllegalArgumentException e){

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditItemResponse(e.getMessage()));
        }

    }

    @DeleteMapping("/{itemId}/delete")
    public ResponseEntity<String> delete_item(@PathVariable Long itemId, HttpServletRequest request){

        String requestUsername = getUsername(request);

        try{
            itemService.delete(itemId, requestUsername);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body("상품이 삭제되었습니다.");
        }catch (NoSuchElementException | IllegalArgumentException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(e.getMessage());
        }

    }


    private String getUsername(HttpServletRequest request){
        String token = request.getHeader("Authorization").split(" ")[1];
        return jwtUtil.getUsername(token);
    }
}
