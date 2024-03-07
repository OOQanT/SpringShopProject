package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "ORDERS")
@Getter
@NoArgsConstructor
public class Order {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL)
    private List<OrderItem> orderItems = new ArrayList<>();

    @CreationTimestamp
    private LocalDateTime orderTime;

    @Enumerated(EnumType.STRING)
    private OrderState status;

    @Enumerated(EnumType.STRING)
    private Payment payment;

    private String delivery;

    @Embedded
    private Address address;

    public void setMember(Member member){
        this.member = member;
    }
    public void setDelivery(String delivery){
        this.delivery = delivery;
    }
    public void addOrderItem(OrderItem orderItem){
        this.orderItems.add(orderItem);
        orderItem.setOrder(this);
    }

    public void setStatus(OrderState status){
        this.status = status;
    }

    public void setPayment(Payment payment){
        this.payment = payment;
    }

    public void setAddress(Address address){
        this.address = address;
    }

    //생성 메서드
    public static Order createOrder(Member member,  List<OrderItem> orderItems){
        Order order = new Order();
        order.setMember(member);
        order.setDelivery("READY");
        for(OrderItem orderItem : orderItems){
            order.addOrderItem(orderItem);
        }
        order.setStatus(OrderState.ORDER);
        return order;
    }

    //비즈니스 로직
    public void cancel(){
        if(getDelivery().equals("COMP")){
            throw new IllegalArgumentException("이미 배송완료된 상품은 취소가 불가능 합니다.");
        }

        this.setStatus(OrderState.CANCEL);
        for(OrderItem orderItem : orderItems){
            orderItem.cancel();
        }
    }

    //전체 주문 가격 조회
    public int getTotalPrice(){
        int totalPrice = 0;
        for(OrderItem orderItem : orderItems){
            totalPrice += orderItem.getTotalPrice();
        }

        return totalPrice;
    }
}
