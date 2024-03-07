package image.upload.uploadtest.repository.comment;

import image.upload.uploadtest.entity.Comment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CommentRepository extends JpaRepository<Comment,Long> {

    List<Comment> findByBoardId(Long boardId);
}
