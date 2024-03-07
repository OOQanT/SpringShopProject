package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Getter
public class ImageFiles {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String storeFilename;
    private String uploadFilename;

    @CreationTimestamp
    private LocalDateTime createTime;

    @UpdateTimestamp
    private LocalDateTime updateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "board_id")
    private Board board;

    public ImageFiles() {
    }

    public ImageFiles(String uploadFilename) {
        this.uploadFilename = uploadFilename;
    }

    public void changeUploadFileName(String uploadFileName){
        this.uploadFilename = uploadFileName;
    }

    public void createStoreFileName(){
        int pos = uploadFilename.lastIndexOf(".");
        String ext = uploadFilename.substring(pos + 1);

        String uuId = UUID.randomUUID().toString();
        this.storeFilename = uuId + "." + ext;
    }

    public void setBoard(Board board){
        this.board = board;
        board.getImageFiles().add(this);
    }
}
