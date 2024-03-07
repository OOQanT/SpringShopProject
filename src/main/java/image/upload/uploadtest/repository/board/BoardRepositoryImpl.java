package image.upload.uploadtest.repository.board;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import image.upload.uploadtest.dto.board.QSearchContentDto;
import image.upload.uploadtest.dto.board.SearchContentDto;
import image.upload.uploadtest.dto.board.SearchCondition;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;

import java.util.List;

import static image.upload.uploadtest.entity.QBoard.board;

@RequiredArgsConstructor
public class BoardRepositoryImpl implements CustomBoardRepository{

    private final JPAQueryFactory query;

    @Override
    public List<SearchContentDto> getContentsByCondition(SearchCondition searchCondition) {

        return query
                .select(new QSearchContentDto(
                        board.id,
                        board.title,
                        board.member.nickname,
                        board.createTime
                ))
                .from(board)
                .where(nicknameEq(searchCondition.getNickname()), titleEq(searchCondition.getTitle()))
                .fetch();
    }

    private BooleanExpression nicknameEq(String nickname){
        return StringUtils.hasText(nickname) ? board.member.nickname.eq(nickname) : null;
    }

    private BooleanExpression titleEq(String title){
        return StringUtils.hasText(title) ? board.title.like("%" + title + "%") : null;
    }
}
