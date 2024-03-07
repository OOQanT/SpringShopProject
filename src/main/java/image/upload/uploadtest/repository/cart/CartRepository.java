package image.upload.uploadtest.repository.cart;

import image.upload.uploadtest.entity.Cart;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface CartRepository extends JpaRepository<Cart,Long>, CustomCartRepository{

    boolean existsByMemberAndItem(Member member, Item item);
    Optional<Cart> findByMemberAndItem(Member member, Item item);
    List<Cart> findByMember(Member member);
}
