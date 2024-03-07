package image.upload.uploadtest.repository.order;

import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface OrderRepository extends JpaRepository<Order,Long> {
    List<Order> findByMember(Member member);
}
