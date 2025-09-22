package org.puchori.springbootproject.service;

import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.dto.*;

import java.util.List;
import java.util.stream.Collectors;

public interface BoardService {
  Long register(BoardDTO boardDTO);

  BoardDTO readOne(Long bno);

  void modify(BoardDTO boardDTO);

  void remove(Long bno);

  PageResponseDTO<BoardDTO> list(PageRequestDTO pageResponseDTO);

  // 댓글의 숫자까지 처리
  PageResponseDTO<BoardListReplyCountDTO> listWithReplyCount(PageRequestDTO pageRequestDTO);

  default Board dtoToEntity(BoardDTO boardDTO){

    Board board = Board.builder()
            .bno(boardDTO.getBno())
            .title(boardDTO.getTitle())
            .content(boardDTO.getContent())
            .writer(boardDTO.getWriter())
            .build();

    if(boardDTO.getFileNames() != null) {
      boardDTO.getFileNames().forEach(fileName -> {
        String[] arr = fileName.split("_",2);
        board.addImage(arr[0], arr[1]);
      });
    }
    return board;
  }

  default BoardDTO entityToDTO(Board board){
    BoardDTO boardDTO = BoardDTO.builder()
            .bno(board.getBno())
            .title(board.getTitle())
            .content(board.getContent())
            .writer(board.getWriter())
            .regDate(board.getRegDate())
            .modDate(board.getModDate())
            .build();

    List<String> fileNames =
            board.getImageSet().stream().sorted().map(boardImage ->
                    boardImage.getUuid()+"_"+boardImage.getFileName()).collect(Collectors.toList());

    boardDTO.setFileNames(fileNames);

    return boardDTO;

  }

  //게시글의 이미지와 댓글의 숫자까지 처리
  PageResponseDTO<BoardListAllDTO> listWithAll(PageRequestDTO pageRequestDTO);

}
