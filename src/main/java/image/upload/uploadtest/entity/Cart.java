package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
public class Cart {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private Item item;

    private int quantity;

    private int total_price;


    public Cart() {
    }

    public Cart(Item item, int quantity) {
        this.item = item;
        this.quantity = quantity;
    }

    public void setMember(Member member){
        this.member = member;
    }

    public void setItem(Item item){
        this.item = item;
    }

    public void setQuantity(int quantity){
        this.quantity = quantity;
    }

    public void totalPrice(){
        this.total_price = item.getPrice() * quantity;
    }


}
