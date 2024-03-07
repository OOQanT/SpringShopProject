package image.upload.uploadtest.service.board;

import image.upload.uploadtest.dto.board.*;
import image.upload.uploadtest.entity.Board;
import image.upload.uploadtest.entity.Member;
import image.upload.uploadtest.repository.board.BoardRepository;
import image.upload.uploadtest.repository.imageFiles.ImageFilesRepository;
import image.upload.uploadtest.repository.member.MemberRepository;
import image.upload.uploadtest.service.imageFiles.ImageFilesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.coyote.BadRequestException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class BoardService {

    private final BoardRepository boardRepository;
    private final MemberRepository memberRepository;
    private final ImageFilesService imageFilesService;
    @Transactional
    public Board save(WriteBoardRequest writeBoardRequest, String requestUsername, boolean isFile){
        Board board = new Board(writeBoardRequest.getTitle(), writeBoardRequest.getContent(),isFile);

        Member findMember = memberRepository.findByUsername(requestUsername)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 사용자"));

        board.setMember(findMember);
        boardRepository.save(board);
        return board;
    }

    public SearchContentResponse findContentsByCondition(SearchCondition searchCondition){
        List<SearchContentDto> findContents = boardRepository.getContentsByCondition(searchCondition);
        if(findContents.isEmpty()){
            throw new NoSuchElementException("게시글이 없음");
        }

        return new SearchContentResponse(findContents, "성공");
    }

    public SearchContentResponse findContents(){
        List<Board> allContents = boardRepository.findAll();
        if(allContents.isEmpty()){
            throw new NoSuchElementException("게시글이 없음");
        }

        List<SearchContentDto> contents = new ArrayList<>();
        for (Board allContent : allContents) {
            contents.add(new SearchContentDto(allContent.getId(), allContent.getTitle(), allContent.getMember().getNickname(),allContent.getCreateTime()));
        }

        return new SearchContentResponse(contents,"성공");
    }

    public Board getContent(Long contentId){
        Optional<Board> findBoard = boardRepository.findById(contentId);
        if(findBoard.isPresent()){
            return findBoard.get();
        }else{
            throw new NoSuchElementException("존재하지 않는 게시물");
        }
    }

    @Transactional
    public boolean editContent(Long id, String requestUsername, EditBoardRequest editBoardRequest) throws IOException {

        Optional<Board> findBoard = boardRepository.findById(id);
        if(findBoard.isEmpty()){
            throw new NoSuchElementException("존재하지 않는 게시글");
        }

        if(!findBoard.get().getMember().getNickname().equals(requestUsername)){
            throw new AccessDeniedException("자신의 게시글만 수정할 수 있습니다.");
        }

        Board board = findBoard.get();
        if(editBoardRequest.getImageFiles() == null || editBoardRequest.getImageFiles().isEmpty()){
            boolean result = imageFilesService.deleteImageFile(id);
            if(result){
                board.changeTitle(editBoardRequest.getTitle());
                board.changeContent(editBoardRequest.getContent());
                board.setIsFile(false);
            }
            return true;
        }else{
            boolean result = imageFilesService.editFromBoard(id, editBoardRequest.getImageFiles(), board);
            if(result){
                board.changeTitle(editBoardRequest.getTitle());
                board.changeContent(editBoardRequest.getContent());
                board.setIsFile(true);
            }
            return true;
        }
    }

    @Transactional
    public boolean delete(Long boardId, String requestUsername){
        Board findBoard = boardRepository.findById(boardId)
                .orElseThrow(() -> new NoSuchElementException("존재하지 않는 게시물"));

        if(!findBoard.getMember().getNickname().equals(requestUsername)){
            throw new IllegalStateException("자신의 글만 수정 가능");
        }

        if(findBoard.isFile()){
            boolean result = imageFilesService.deleteImageFile(boardId);
            if(result){
                boardRepository.delete(findBoard);
            }
        }else{
            boardRepository.delete(findBoard);
        }
        return true;
    }

}
