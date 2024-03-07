package image.upload.uploadtest.repository.board;

import image.upload.uploadtest.dto.board.SearchContentDto;
import image.upload.uploadtest.dto.board.SearchCondition;

import java.util.List;

public interface CustomBoardRepository {
    List<SearchContentDto> getContentsByCondition(SearchCondition searchCondition);

}
