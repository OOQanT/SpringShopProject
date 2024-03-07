package image.upload.uploadtest.dto.item;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Range;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Getter
@Setter
public class EditItemRequest {

    @NotEmpty(message = "제품명을 입력해주세요")
    private String itemName;

    @NotNull(message = "가격을 입력해주세요.")
    @Min(value = 100, message = "가격은 100원 이상 이어야 합니다")
    private int price;

    @NotNull(message = "수량을 입력해주세요.")
    @Range(min = 1, max = 9999, message = "수량은  1 ~ 999 까지 입니다.")
    private int quantity;

    private String description;

    private List<MultipartFile> itemImages;

    public EditItemRequest() {
    }

    public EditItemRequest(String itemName, int price, int quantity, String description) {
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.description = description;
    }

    public EditItemRequest(String itemName, int price, int quantity, String description,List<MultipartFile> itemImages) {
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
        this.description = description;
        this.itemImages = itemImages;
    }
}
