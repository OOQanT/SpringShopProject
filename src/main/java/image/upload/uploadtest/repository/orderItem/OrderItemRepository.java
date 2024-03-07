package image.upload.uploadtest.repository.orderItem;

import image.upload.uploadtest.entity.Order;
import image.upload.uploadtest.entity.OrderItem;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface OrderItemRepository extends JpaRepository<OrderItem,Long> {
    List<OrderItem> findByOrder(Order order);
}
