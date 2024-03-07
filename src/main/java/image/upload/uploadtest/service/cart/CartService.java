package image.upload.uploadtest.service.cart;

import image.upload.uploadtest.dto.cart.GetCartDto;
import image.upload.uploadtest.entity.Cart;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.cart.CartRepository;
import image.upload.uploadtest.repository.item.ItemRepository;
import image.upload.uploadtest.repository.member.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class CartService {

    private final CartRepository cartRepository;
    private final MemberRepository memberRepository;
    private final ItemRepository itemRepository;

    public Cart addItem(String requestUsername, Long itemId, int quantity){
        Member findMember = memberRepository.findByUsername(requestUsername)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 사용자입니다."));

        Item findItem = itemRepository.findById(itemId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 상품입니다."));

        if(findItem.getQuantity() - quantity < 0){
            throw new IllegalStateException("재고가 부족합니다.");
        }

        boolean result = cartRepository.existsByMemberAndItem(findMember, findItem);
        if(result){
            Cart findCart = cartRepository.findByMemberAndItem(findMember, findItem)
                    .orElseThrow(() -> new NoSuchElementException("존재하지 않는 목록"));

            if( findItem.getQuantity() - (findCart.getQuantity() + quantity) < 0){
                throw new IllegalStateException("추가하는 만큼의 재고가 부족합니다.");
            }
            findCart.setQuantity(findCart.getQuantity() + quantity);
            findCart.totalPrice();
            return findCart;
        }else{
            Cart cart = new Cart(findItem,quantity);
            cart.setMember(findMember);
            cart.totalPrice();
            cartRepository.save(cart);
            return cart;
        }
    }

    public Cart editQuantity(Long cartId, int quantity, String requestUsername){
        Cart findCart = cartRepository.findById(cartId)
                .orElseThrow(() -> new NoSuchElementException("존재 하지않는 목록"));

        if(!findCart.getMember().getUsername().equals(requestUsername)){
            throw new IllegalArgumentException("상품 목록의 주인이 아닙니다.");
        }

        findCart.setQuantity(quantity);
        findCart.totalPrice();
        return findCart;
    }

    public boolean delete(Long cartId, String requestUsername){
        Cart findCart = cartRepository.findById(cartId)
                .orElseThrow(() -> new NoSuchElementException("존재 하지않는 목록"));

        if(!findCart.getMember().getUsername().equals(requestUsername)){
            throw new IllegalArgumentException("상품 목록의 주인이 아닙니다.");
        }

        cartRepository.delete(findCart);
        return true;
    }

    public List<GetCartDto> getCartList(String requestUsername){

        List<GetCartDto> cartList = cartRepository.getCartList(requestUsername);

        return cartList;
    }

}
