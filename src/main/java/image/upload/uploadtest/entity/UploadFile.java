package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;

import java.util.UUID;

@Entity
@Getter
public class UploadFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String storeFilename;
    private String uploadFilename;

    public UploadFile() {
    }

    public UploadFile(String uploadFilename) {
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

}
