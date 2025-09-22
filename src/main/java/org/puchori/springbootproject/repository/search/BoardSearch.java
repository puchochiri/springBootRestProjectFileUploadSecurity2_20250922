package org.puchori.springbootproject.repository.search;


import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface BoardSearch {

  Page<Board> search1(Pageable pageable);

  Page<Board> searchAll(String[] types, String keyword, Pageable pageable);

  Page<BoardListReplyCountDTO> searchWithReplyCount(String[] types, String keyword, Pageable pageable);

  Page<BoardListAllDTO> searchWithAll(String[] types, String keyword, Pageable pageable);

  Page<BoardListAllDTO> listWithAll(PageRequestDTO pageRequestDTO);

  default Board dtoToEntity(BoardDTO boardDTO){
    Board board = new Board();

    return board;

  }





}
