package image.upload.uploadtest.controller.board;

import image.upload.uploadtest.dto.ErrorResponse;
import image.upload.uploadtest.dto.board.*;
import image.upload.uploadtest.entity.Board;
import image.upload.uploadtest.entity.ImageFiles;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.service.board.BoardService;
import image.upload.uploadtest.service.imageFiles.ImageFilesService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/board")
public class BoardController {

    @Value("${file.dir}")
    private String fileDir;

    private final BoardService boardService;
    private final ImageFilesService imageFilesService;
    private final JWTUtil jwtUtil;

    @PostMapping("/write")
    public ResponseEntity<WriteBoardResponse> writeFile_content(@Validated @ModelAttribute WriteBoardRequest writeBoardRequest, BindingResult bindingResult,
                                                                HttpServletRequest request){

        if(bindingResult.hasErrors()){
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();
            List<String> collect = fieldErrors.stream().map(m -> m.getDefaultMessage()).collect(Collectors.toList());

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new WriteBoardResponse(collect));
        }

        String token = request.getHeader("Authorization").split(" ")[1];
        String requestUsername = jwtUtil.getUsername(token);

        List<String> message = new ArrayList<>();
        try{
            if(writeBoardRequest.getImageFiles() == null || writeBoardRequest.getImageFiles().isEmpty()){
                Board savedBoard = boardService.save(writeBoardRequest, requestUsername, false);
                message.add("성공");
                return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                        .body(new WriteBoardResponse(savedBoard.getTitle(),savedBoard.getMember().getNickname(),message));
            }else{
                Board savedBoard = boardService.save(writeBoardRequest, requestUsername, true);
                imageFilesService.save(writeBoardRequest,savedBoard);
                message.add("성공");
                return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                        .body(new WriteBoardResponse(savedBoard.getTitle(),savedBoard.getMember().getNickname(),message));
            }
        }catch (NoSuchElementException e){
            message.add("존재하지 않는 사용자의 요청");
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new WriteBoardResponse(message));
        } catch (IOException e) {
            message.add("파일 저장 실패");
            return ResponseEntity.status(HttpServletResponse.SC_ACCEPTED)
                    .body(new WriteBoardResponse(message));

        }
    }

    @PostMapping("/contents_condition")
    public ResponseEntity<SearchContentResponse> getContentsByCondition(@RequestBody SearchCondition searchCondition){
        try{
            SearchContentResponse contents = boardService.findContentsByCondition(searchCondition);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(contents);
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new SearchContentResponse("게시글이 존재하지 않습니다."));
        }
    }


    @GetMapping("/contents")
    public ResponseEntity<SearchContentResponse> getContents(){
        try{
            SearchContentResponse contents = boardService.findContents();
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(contents);
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new SearchContentResponse("게시글이 존재하지 않습니다."));
        }
    }

    @GetMapping("/contents/{id}")
    public ResponseEntity<GetBoardResponse> getContent(@PathVariable Long id){
        try{
            Board content = boardService.getContent(id);
            if(content.isFile()){
                List<String> imageFiles = imageFilesService.getImageFiles(content.getId());
                return ResponseEntity.status(HttpServletResponse.SC_OK)
                        .body(new GetBoardResponse(content,imageFiles,"성공"));
            }
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new GetBoardResponse(content, "성공"));
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new GetBoardResponse(e.getMessage()));
        }
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

    @PutMapping("/{id}/edit")
    public ResponseEntity<EditBoardResponse> edit(@PathVariable Long id, HttpServletRequest request,
                     @Validated @ModelAttribute EditBoardRequest editBoardRequest, BindingResult bindingResult) throws IOException {

        if(bindingResult.hasErrors()){
            List<FieldError> fieldErrors = bindingResult.getFieldErrors();
            List<String> collect = fieldErrors.stream().map(m -> m.getDefaultMessage()).collect(Collectors.toList());

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditBoardResponse(collect));
        }

        String token = request.getHeader("Authorization").split(" ")[1];
        String requestUsername = jwtUtil.getUsername(token);

        List<String> messages = new ArrayList<>();
        try{
            boolean result = boardService.editContent(id, requestUsername, editBoardRequest);
            if(result){
                messages.add("성공");
                return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                        .body(new EditBoardResponse(editBoardRequest.getTitle(),requestUsername,messages));
            }else{
                messages.add("실패");
                return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                        .body(new EditBoardResponse(messages));
            }

        } catch (NoSuchElementException | FileSystemException e){
            messages.add(e.getMessage());
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditBoardResponse(messages));
        }
    }

    @DeleteMapping("/{id}/delete")
    public ResponseEntity<String> delete(@PathVariable Long id, HttpServletRequest request){

        String token = request.getHeader("Authorization").split(" ")[1];
        String requestUsername = jwtUtil.getUsername(token);

        try{
            boardService.delete(id,requestUsername);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body("게시글이 삭제되었습니다.");
        }catch (NoSuchElementException | IllegalStateException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(e.getMessage());
        }

    }


}
