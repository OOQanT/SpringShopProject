package image.upload.uploadtest.repository.cart;

import image.upload.uploadtest.dto.cart.GetCartDto;

import java.util.List;

public interface CustomCartRepository {
    List<GetCartDto> getCartList(String username);
}
