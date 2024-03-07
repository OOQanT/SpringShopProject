package image.upload.uploadtest.entity;

import com.querydsl.core.annotations.QueryProjection;
import image.upload.uploadtest.dto.item.ItemRegisterRequest;
import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Getter
public class Item {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String itemName;
    private int price;
    private int quantity;
    private String description;

    private boolean isFile;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    @CreationTimestamp
    private LocalDateTime createTime;

    @UpdateTimestamp
    private LocalDateTime updateTime;


    public Item() {

    }

    public Item(String itemName, int price, int quantity, String description) {
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.description = description;
    }

    @QueryProjection
    public Item(Long id, String itemName, int price, int quantity, String description, boolean isFile) {
        this.id = id;
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.description = description;
        this.isFile = isFile;
    }

    public Item(ItemRegisterRequest itemRegisterRequest){
        this.itemName = itemRegisterRequest.getItemName();
        this.price = itemRegisterRequest.getPrice();
        this.quantity = itemRegisterRequest.getQuantity();
        this.description = itemRegisterRequest.getDescription();
    }

    public void setMember(Member member){
        this.member = member;
    }

    public void setIsFile(boolean isFile){
        this.isFile = isFile;
    }

    public void setItemName(String itemName){
        this.itemName = itemName;
    }

    public void setPrice(int price){
        this.price = price;
    }

    public void setQuantity(int quantity){
        this.quantity = quantity;
    }

    public void setDescription(String description){
        this.description = description;
    }

    public void addQuantity(int count){
        this.quantity = this.quantity + count;
    }

    public void removeStock(int count) {
        this.quantity -= count;
    }
}
