package image.upload.uploadtest.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Getter
@Entity
public class Board {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String title;
    private String content;

    @CreationTimestamp
    private LocalDateTime createTime;

    @UpdateTimestamp
    private LocalDateTime updateTime;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id")
    private Member member;

    private boolean isFile;

    @OneToMany(mappedBy = "board", cascade = CascadeType.REMOVE)
    private List<ImageFiles> imageFiles = new ArrayList<>();

    public Board() {
    }

    public Board(String title, String content, boolean isFile) {
        this.title = title;
        this.content = content;
        this.isFile = isFile;
    }

    public Board(String title, String content) {
        this.title = title;
        this.content = content;
    }

    public void setIsFile(boolean isFile){
        this.isFile = isFile;
    }

    public void setMember(Member member){
        this.member = member;
    }

    public void changeTitle(String title){
        this.title = title;
    }

    public void changeContent(String content){
        this.content = content;
    }
}
