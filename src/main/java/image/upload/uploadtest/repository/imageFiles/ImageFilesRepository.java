package image.upload.uploadtest.repository.imageFiles;

import image.upload.uploadtest.entity.ImageFiles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface ImageFilesRepository extends JpaRepository<ImageFiles,Long> {
    List<ImageFiles> findByBoardId(Long BoardId);

}
