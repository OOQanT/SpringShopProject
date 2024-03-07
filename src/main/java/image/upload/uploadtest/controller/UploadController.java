package image.upload.uploadtest.controller;

import image.upload.uploadtest.dto.FilenameResponse;
import image.upload.uploadtest.dto.SaveFileDto;
import image.upload.uploadtest.entity.UploadFile;
import image.upload.uploadtest.service.UploadFileService;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URLEncoder;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@RestController
@RequiredArgsConstructor
public class UploadController {

    private final UploadFileService uploadFileService;
    @Value("${file.dir}")
    private String fileDir;

    @PostMapping("/images/saveFile")
    public void saveFile(@ModelAttribute SaveFileDto saveFileDto, HttpServletResponse response) throws IOException {

        if(saveFileDto.getFiles().isEmpty()){
            response.setStatus(400);
            return;
        }
        uploadFileService.save(saveFileDto);
    }


    @GetMapping("/images/getFilename")
    public List<FilenameResponse> getFilename(HttpServletResponse response){
        List<UploadFile> all = uploadFileService.findAll();

        List<FilenameResponse> files = new ArrayList<>();
        for (UploadFile uploadFile : all) {
            files.add(new FilenameResponse(uploadFile.getStoreFilename()));
        }

        return files;
    }


    @GetMapping("/images/{filename}")
    public ResponseEntity<Resource> downloadExecute(@PathVariable("filename") String filename) throws IOException {
        log.info("Full Path = {}", fileDir + filename);

        String str = URLEncoder.encode(filename, "UTF-8");

        Path path = Paths.get(fileDir + filename);
        Resource resource = new InputStreamResource(java.nio.file.Files.newInputStream(path));
        System.out.println("resource : "+ resource.getFilename());

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_TYPE, "application/octect-stream")
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename="+str+";")
                .body(resource);
    }

    //@GetMapping("/images/{filename}")
    public Resource downloadImage(@PathVariable String filename) throws MalformedURLException {
        return new UrlResource("file:" + fileDir + filename);
    }
}
