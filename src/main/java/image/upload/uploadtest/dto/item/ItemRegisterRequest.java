package image.upload.uploadtest.dto.item;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Range;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Setter
@Getter
public class ItemRegisterRequest {

    @NotEmpty(message = "상품명을 입력해주세요")
    private String itemName;

    @NotNull(message = "가격을 입력해주세요")
    @Min(value = 100, message = "가격은 100 이상이여야 합니다.")
    private int price;

    @NotNull(message = "수량을 입력해주세요")
    @Range(min = 1, max = 9999, message = "수량은 1~9999 까지 입니다.")
    private int quantity;

    @NotEmpty(message = "상품 설명을 입력해 주세요")
    private String description;

    private List<MultipartFile> imageFiles;

    public ItemRegisterRequest() {

    }

    public ItemRegisterRequest(String itemName, int price, int quantity) {
        this.itemName = itemName;
        this.price = price;
        this.quantity = quantity;
    }
}
