package image.upload.uploadtest.service.comment;

import image.upload.uploadtest.dto.comment.EditCommentRequest;
import image.upload.uploadtest.dto.comment.WriteCommentRequest;
import image.upload.uploadtest.entity.Board;
import image.upload.uploadtest.entity.Comment;
import image.upload.uploadtest.repository.board.BoardRepository;
import image.upload.uploadtest.repository.comment.CommentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.AccessDeniedException;
import java.util.List;
import java.util.NoSuchElementException;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class CommentService {

    private final CommentRepository commentRepository;
    private final BoardRepository boardRepository;

    public Comment write(Long boardId, String requestUsername, WriteCommentRequest writeCommentRequest){
        Board findBoard = boardRepository.findById(boardId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 게시글"));

        Comment comment = new Comment(requestUsername, writeCommentRequest.getComment());
        comment.setBoard(findBoard);

        commentRepository.save(comment);

        return comment;
    }

    public List<Comment> getComments(Long boardId){
        List<Comment> findComments = commentRepository.findByBoardId(boardId);
        if(findComments == null || findComments.isEmpty()){
            throw new NoSuchElementException("댓글이 존재하지 않습니다.");
        }
        return findComments;
    }

    public Comment edit(Long commentId, String requestUsername, EditCommentRequest editCommentRequest){

        Comment findComment = commentRepository.findById(commentId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 댓글"));

        if(!findComment.getNickname().equals(requestUsername)){
            throw new IllegalArgumentException("타인의 글은 수정할 수 없습니다.");
        }

        findComment.changeComment(editCommentRequest.getComment());
        return findComment;
    }

    public boolean delete(Long commentId, String requestUsername){
        Comment findComment = commentRepository.findById(commentId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 댓글"));

        if(!findComment.getNickname().equals(requestUsername)){
            throw new IllegalArgumentException("타인의 글은 삭제할 수 없습니다.");
        }

        commentRepository.delete(findComment);
        return true;
    }
}
