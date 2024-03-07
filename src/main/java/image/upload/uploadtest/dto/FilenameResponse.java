package image.upload.uploadtest.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FilenameResponse {

    private String storeFilename;

    public FilenameResponse() {
    }

    public FilenameResponse(String storeFilename) {
        this.storeFilename = storeFilename;
    }
}
