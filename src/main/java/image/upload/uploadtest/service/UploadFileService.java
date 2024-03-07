package image.upload.uploadtest.service;

import image.upload.uploadtest.dto.SaveFileDto;
import image.upload.uploadtest.entity.UploadFile;
import image.upload.uploadtest.repository.UploadFileRepository;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class UploadFileService {

    @Value("${file.dir}")
    private String fileDir;

    private final UploadFileRepository uploadFileRepository;

    public boolean save(SaveFileDto saveFileDto) throws IOException {

        List<MultipartFile> imageFiles = saveFileDto.getFiles();
        for (MultipartFile imageFile : imageFiles) {
            UploadFile file = new UploadFile(imageFile.getOriginalFilename());
            file.createStoreFileName();

            imageFile.transferTo(new File(fileDir + file.getStoreFilename()));
            uploadFileRepository.save(file);
        }

        return true;
    }

    public List<UploadFile> findAll(){
        List<UploadFile> all = uploadFileRepository.findAll();
        return all;
    }

}
