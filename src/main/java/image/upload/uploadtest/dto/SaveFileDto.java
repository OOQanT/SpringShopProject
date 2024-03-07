package image.upload.uploadtest.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Getter
@Setter
public class SaveFileDto {

    private List<MultipartFile> files;

    public SaveFileDto() {
    }

    public SaveFileDto(List<MultipartFile> files) {
        this.files = files;
    }
}
