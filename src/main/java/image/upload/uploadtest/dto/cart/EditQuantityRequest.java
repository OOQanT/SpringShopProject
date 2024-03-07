package image.upload.uploadtest.dto.cart;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class EditQuantityRequest {

    @NotNull
    @Min(value = 1,message = "수량은 1 이상이어야 합니다.")
    private int quantity;
    public EditQuantityRequest() {
    }

    public EditQuantityRequest(int quantity) {
        this.quantity = quantity;
    }
}
