package image.upload.uploadtest.controller.cart;

import image.upload.uploadtest.dto.cart.*;
import image.upload.uploadtest.entity.Cart;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.repository.cart.CartRepository;
import image.upload.uploadtest.service.cart.CartService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/cart")
public class CartController {

    private final CartService cartService;
    private final JWTUtil jwtUtil;

    @PostMapping("/addItem")
    public ResponseEntity<AddItemResponse> addItem(@RequestBody AddItemRequest addItemRequest, HttpServletRequest request){
        String requestUsername = getUsername(request);

        try{
            Cart cart = cartService.addItem(requestUsername, addItemRequest.getItemId(), addItemRequest.getQuantity());

            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new AddItemResponse(cart.getItem().getId(), cart.getQuantity(), "성공"));
        }catch (NoSuchElementException | IllegalStateException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new AddItemResponse(e.getMessage()));
        }

    }

    @PutMapping("/{cartId}/edit")
    public ResponseEntity<EditQuantityResponse> edit_cart(@PathVariable Long cartId, HttpServletRequest request,
                                                          @Validated @RequestBody EditQuantityRequest editQuantityRequest,
                                                          BindingResult bindingResult){

        if(bindingResult.hasErrors()){
            if (bindingResult.getFieldError().getCode().equals("typeMismatch")){
                return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                        .body(new EditQuantityResponse("정수를 입력해주세요."));
            }else{
                return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                        .body(new EditQuantityResponse(bindingResult.getFieldError().getDefaultMessage()));
            }
        }

        String requestUsername = getUsername(request);
        try{
            Cart cart = cartService.editQuantity(cartId, editQuantityRequest.getQuantity(), requestUsername);
            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new EditQuantityResponse(cart.getId(),cart.getQuantity(),"성공"));
        }catch (NoSuchElementException | IllegalArgumentException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditQuantityResponse(e.getMessage()));
        }
    }

    @DeleteMapping("/{cartId}/delete")
    public ResponseEntity<DeleteCartResponse> delete(@PathVariable Long cartId, HttpServletRequest request){
        String requestUsername = getUsername(request);
        try{
            cartService.delete(cartId,requestUsername);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new DeleteCartResponse(cartId,"성공"));
        }catch (NoSuchElementException | IllegalArgumentException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new DeleteCartResponse(e.getMessage()));
        }
    }

    @GetMapping("/cartList")
    public ResponseEntity<GetCartResponse> cartList(HttpServletRequest request){
        String requestUsername = getUsername(request);

        List<GetCartDto> cartList = cartService.getCartList(requestUsername);

        return ResponseEntity.status(HttpServletResponse.SC_OK)
                .body(new GetCartResponse(cartList,"성공"));
    }


    private String getUsername(HttpServletRequest request){
        String token = request.getHeader("Authorization").split(" ")[1];
        return jwtUtil.getUsername(token);
    }
}
