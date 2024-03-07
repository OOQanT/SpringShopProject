package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@NoArgsConstructor
public class OrderItem {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private Item item;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "order_id")
    private Order order;

    private int orderPrice;
    private int count;

    private int totalOrderPrice;


    public void setItem(Item item){
        this.item = item;
    }

    public void setOrder(Order order){
        this.order = order;
        order.getOrderItems().add(this);
    }

    public void setOrderPrice(int orderPrice) {
        this.orderPrice = orderPrice;
    }

    public void setCount(int count) {
        this.count = count;
    }

    //비즈니스 로직
    public void cancel() {
        getItem().addQuantity(count);
    }

    public int getTotalPrice(){
        return getOrderPrice() * getCount();
    }
    public void setTotalPrice(int price, int quantity){
        this.totalOrderPrice = price * quantity;
    }

    public static List<OrderItem> createOrderItem(List<Cart> carts){

        List<OrderItem> orderItems = new ArrayList<>();

        for (Cart cart : carts) {
            OrderItem orderItem = new OrderItem();
            orderItem.setItem(cart.getItem());
            orderItem.setOrderPrice(cart.getItem().getPrice());
            orderItem.setCount(cart.getQuantity());
            orderItem.setTotalPrice(cart.getItem().getPrice(),cart.getQuantity());

            cart.getItem().removeStock(cart.getQuantity());

            orderItems.add(orderItem);
        }

        return orderItems;
    }
}
