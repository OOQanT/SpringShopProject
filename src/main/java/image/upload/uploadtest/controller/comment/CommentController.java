package image.upload.uploadtest.controller.comment;

import image.upload.uploadtest.dto.comment.*;
import image.upload.uploadtest.entity.Comment;
import image.upload.uploadtest.jwt.JWTUtil;
import image.upload.uploadtest.service.comment.CommentService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/comment")
public class CommentController {

    private final CommentService commentService;
    private final JWTUtil jwtUtil;

    @PostMapping("/{id}/write")
    public ResponseEntity<WriteCommentResponse> write_comment(
            @PathVariable Long id, HttpServletRequest request,
            @Validated @RequestBody WriteCommentRequest writeCommentRequest, BindingResult bindingResult){

        if(bindingResult.hasErrors()){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new WriteCommentResponse("댓글을 입력해주세요"));
        }

        String requestUsername = getRequestUsername(request);

        try{
            Comment savedComment = commentService.write(id, requestUsername, writeCommentRequest);
            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new WriteCommentResponse(savedComment.getComment(), savedComment.getNickname(), "성공"));
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NOT_FOUND)
                    .body(new WriteCommentResponse(e.getMessage()));
        }
    }

    @GetMapping("/{id}/comments")
    public ResponseEntity<GetCommentResponse> getComments(@PathVariable Long id){

        try{
            List<Comment> comments = commentService.getComments(id);
            List<GetCommentsDto> commentList = new ArrayList<>();
            for (Comment comment : comments) {
                GetCommentsDto getCommentsDto = new GetCommentsDto(comment.getId(),comment.getComment(), comment.getNickname(), comment.getCreateTime());
                commentList.add(getCommentsDto);
            }
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new GetCommentResponse(commentList,"성공"));
        }catch (NoSuchElementException e){
            return ResponseEntity.status(HttpServletResponse.SC_NO_CONTENT)
                    .body(new GetCommentResponse("댓글이 없음"));
        }

    }

    @PutMapping("/{commentId}/edit")
    public ResponseEntity<EditCommentResponse> edit_comment(@PathVariable Long commentId, HttpServletRequest request,
                             @Validated @RequestBody EditCommentRequest editCommentRequest,BindingResult bindingResult){

        if(bindingResult.hasErrors()){
            String defaultMessage = bindingResult.getFieldError().getDefaultMessage();
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditCommentResponse(defaultMessage));
        }

        String requestUsername = getRequestUsername(request);

        try{

            Comment edit = commentService.edit(commentId, requestUsername, editCommentRequest);
            return ResponseEntity.status(HttpServletResponse.SC_CREATED)
                    .body(new EditCommentResponse(edit.getComment(), edit.getNickname(), "성공"));

        }catch (NoSuchElementException | IllegalArgumentException e){

            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new EditCommentResponse(e.getMessage()));

        }

    }

    @DeleteMapping("/{commentId}/delete")
    public ResponseEntity<DeleteCommentResponse> delete_comment(@PathVariable Long commentId, HttpServletRequest request){
        String requestUsername = getRequestUsername(request);

        try{
            commentService.delete(commentId,requestUsername);
            return ResponseEntity.status(HttpServletResponse.SC_OK)
                    .body(new DeleteCommentResponse("삭제 성공"));

        }catch (NoSuchElementException | IllegalArgumentException e){
            return ResponseEntity.status(HttpServletResponse.SC_BAD_REQUEST)
                    .body(new DeleteCommentResponse(e.getMessage()));
        }

    }

    private String getRequestUsername(HttpServletRequest request){
        String token = request.getHeader("Authorization").split(" ")[1];
        return jwtUtil.getUsername(token);
    }
}
