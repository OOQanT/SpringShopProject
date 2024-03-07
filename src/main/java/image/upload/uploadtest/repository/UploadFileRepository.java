package image.upload.uploadtest.repository;

import image.upload.uploadtest.entity.UploadFile;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UploadFileRepository extends JpaRepository<UploadFile,Long> {

}


