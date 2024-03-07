package image.upload.uploadtest.entity;

import jakarta.persistence.Embeddable;
import lombok.Getter;

@Embeddable
@Getter
public class Address {

    private String address;
    private String detailAddress;

    public Address() {
    }

    public Address(String address, String detailAddress) {
        this.address = address;
        this.detailAddress = detailAddress;
    }
}
