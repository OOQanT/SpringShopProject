package image.upload.uploadtest.service.imageFiles;

import image.upload.uploadtest.dto.board.EditBoardRequest;
import image.upload.uploadtest.dto.board.WriteBoardRequest;
import image.upload.uploadtest.entity.Board;
import image.upload.uploadtest.entity.ImageFiles;
import image.upload.uploadtest.repository.board.BoardRepository;
import image.upload.uploadtest.repository.imageFiles.ImageFilesRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystemException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class ImageFilesService {

    @Value("${file.dir}")
    private String fileDir;

    private final ImageFilesRepository imageFilesRepository;
    private final BoardRepository boardRepository;

    public boolean save(WriteBoardRequest writeBoardRequest, Board board) throws IOException {
        List<MultipartFile> imageFiles = writeBoardRequest.getImageFiles();

        for (MultipartFile imageFile : imageFiles) {
            ImageFiles image = new ImageFiles(imageFile.getOriginalFilename());
            image.createStoreFileName();
            image.setBoard(board);

            imageFile.transferTo(new File(fileDir + image.getStoreFilename()));
            imageFilesRepository.save(image);
        }
        return true;
    }

    public boolean editFromBoard(Long boardId,List<MultipartFile> imageFiles,Board board) throws IOException {
        List<ImageFiles> findImages = imageFilesRepository.findByBoardId(boardId);

        if(findImages.isEmpty()){
            for (MultipartFile imageFile : imageFiles) {
                ImageFiles files = new ImageFiles(imageFile.getOriginalFilename());
                files.createStoreFileName();
                files.setBoard(board);

                imageFile.transferTo(new File(fileDir + files.getStoreFilename()));
                imageFilesRepository.save(files);
            }
            return true;
        }else{
            for (ImageFiles findImage : findImages) {
                File file = new File(fileDir + findImage.getStoreFilename());
                if(file.exists()){
                    if(!file.delete()){
                        throw new FileSystemException("파일 삭제 실패");
                    }else{
                        imageFilesRepository.delete(findImage);
                    }
                }else{
                    throw new NoSuchFileException("존재하지 않는 파일");
                }
            }
            for (MultipartFile imageFile : imageFiles) {
                ImageFiles files = new ImageFiles(imageFile.getOriginalFilename());
                files.createStoreFileName();
                files.setBoard(board);

                imageFile.transferTo(new File(fileDir + files.getStoreFilename()));
                imageFilesRepository.save(files);
            }
            return true;
        }
    }

    public boolean deleteImageFile(Long boardId){

        List<ImageFiles> findImages = imageFilesRepository.findByBoardId(boardId);
        if(findImages.isEmpty()){
            return true;
        }

        for (ImageFiles findImage : findImages) {
            File file = new File(fileDir + findImage.getStoreFilename());
            boolean delete = file.delete();
            if(!delete){
                return false;
            }
            imageFilesRepository.delete(findImage);
        }

        return true;
    }

    public List<String> getImageFiles(Long boardId){
        List<ImageFiles> findImages = imageFilesRepository.findByBoardId(boardId);
        if(findImages.isEmpty()){
            throw new NoSuchElementException("파일을 찾을 수 없습니다");
        }

        List<String> filenames = new ArrayList<>();
        for (ImageFiles findImage : findImages) {
            filenames.add(findImage.getStoreFilename());
        }

        return filenames;
    }
}
