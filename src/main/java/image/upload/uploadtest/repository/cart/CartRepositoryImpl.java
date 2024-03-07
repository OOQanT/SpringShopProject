package image.upload.uploadtest.repository.cart;

import com.querydsl.jpa.impl.JPAQueryFactory;
import image.upload.uploadtest.dto.cart.GetCartDto;
import image.upload.uploadtest.dto.cart.QGetCartDto;
import image.upload.uploadtest.entity.QCart;
import lombok.RequiredArgsConstructor;

import java.util.List;

import static image.upload.uploadtest.entity.QCart.*;

@RequiredArgsConstructor
public class CartRepositoryImpl implements CustomCartRepository{

    private final JPAQueryFactory query;

    @Override
    public List<GetCartDto> getCartList(String username) {

        List<GetCartDto> fetch = query
                .select(new QGetCartDto(
                        cart.id,
                        cart.item.itemName,
                        cart.item.price,
                        cart.quantity,
                        cart.total_price
                ))
                .from(cart)
                .where(cart.member.username.eq(username))
                .fetch();

        return fetch;
    }
}
