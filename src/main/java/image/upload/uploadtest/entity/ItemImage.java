package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Getter
public class ItemImage {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String storeFilename;
    private String uploadFilename;

    @CreationTimestamp
    private LocalDateTime createTime;

    @UpdateTimestamp
    private LocalDateTime updateTime;


    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "item_id")
    private Item item;

    public ItemImage() {
    }

    public ItemImage(String uploadFilename) {
        this.uploadFilename = uploadFilename;
    }

    public void createStoreFileName(){
        int pos = uploadFilename.lastIndexOf(".");
        String ext = uploadFilename.substring(pos + 1);

        String uuId = UUID.randomUUID().toString();
        this.storeFilename = uuId + "." + ext;
    }

    public void setItem(Item item){
        this.item = item;
    }
}
