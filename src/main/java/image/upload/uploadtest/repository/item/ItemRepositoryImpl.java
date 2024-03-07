package image.upload.uploadtest.repository.item;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import image.upload.uploadtest.dto.item.GetItemsDto;
import image.upload.uploadtest.dto.item.QGetItemsDto;
import image.upload.uploadtest.entity.Item;
import image.upload.uploadtest.entity.QItem;
import lombok.RequiredArgsConstructor;
import org.springframework.util.StringUtils;

import java.util.List;

import static image.upload.uploadtest.entity.QItem.*;

@RequiredArgsConstructor
public class ItemRepositoryImpl implements CustomItemRepository{

    private final JPAQueryFactory query;

    @Override
    public List<GetItemsDto> findItemsByCondition(String itemName) {

        return query
                .select(new QGetItemsDto(
                        item.id,
                        item.member.nickname.as("seller"),
                        item.itemName,
                        item.price,
                        item.quantity,
                        item.isFile
                ))
                .from(item)
                .where(itemNameLike(itemName))
                .fetch();
    }

    @Override
    public List<Item> findByItemsByCondition(String itemName) {

        List<Item> fetch = query
                .select(item)
                .from(item)
                .where(itemNameLike(itemName))
                .fetch();

        return fetch;
    }

    private BooleanExpression itemNameLike(String itemName){
        return StringUtils.hasText(itemName) ? item.itemName.like("%" + itemName + "%") : null;
    }
}
