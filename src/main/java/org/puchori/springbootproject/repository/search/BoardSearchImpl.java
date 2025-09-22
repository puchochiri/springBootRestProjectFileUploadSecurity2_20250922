package org.puchori.springbootproject.repository.search;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.Tuple;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.JPQLQuery;
import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.domain.QBoard;
import org.puchori.springbootproject.domain.QReply;
import org.puchori.springbootproject.dto.*;
import org.puchori.springbootproject.repository.BoardRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;

import java.util.List;
import java.util.stream.Collectors;

public class BoardSearchImpl extends QuerydslRepositorySupport implements BoardSearch {


  /**
   * Creates a new {@link QuerydslRepositorySupport} instance for the given domain type.
   *
   */
  public BoardSearchImpl() {
    super(Board.class);
  }


  @Override
  public Page<Board> search1(Pageable pageable) {

    QBoard board = QBoard.board; // Q도메인 객체

    JPQLQuery<Board> query = from(board); //select.. from board

    query.where(board.title.contains("1")); // where title like

    //paging
    this.getQuerydsl().applyPagination(pageable, query);

    List<Board> list = query.fetch();

    long count = query.fetchCount();

    return new PageImpl<>(list, pageable, count);
  }

  @Override
  public Page<Board> searchAll(String[] types, String keyword, Pageable pageable) {

    QBoard board = QBoard.board;

    JPQLQuery<Board> query = from(board);

    if((types != null && types.length > 0) && keyword != null) {
      // 검색 조건과 키워드가 있다면
      BooleanBuilder booleanBuilder= new BooleanBuilder();

      for (String type: types){
        switch (type){
          case "t":
            booleanBuilder.or(board.title.contains(keyword));
            break;
          case "c":
            booleanBuilder.or(board.content.contains(keyword));
            break;
          case "w":
            booleanBuilder.or(board.writer.contains(keyword));
            break;
        }

      } // end for
      query.where(booleanBuilder);
    } // end if

    // bno > 0
    query.where(board.bno.gt(0L));

    // paging
    this.getQuerydsl().applyPagination(pageable, query);

    List<Board> list = query.fetch();

    long count = query.fetchCount();

    return  new PageImpl<>(list, pageable, count);

  }

  @Override
  public Page<BoardListReplyCountDTO> searchWithReplyCount(String[] types, String keyword, Pageable pageable) {

    QBoard board = QBoard.board;
    QReply reply = QReply.reply;

    JPQLQuery<Board> query = from(board);
    query.leftJoin(reply).on(reply.board.eq(board));
    query.groupBy(board);

    if((types != null && types.length > 0) && keyword !=null){
      BooleanBuilder booleanBuilder = new BooleanBuilder();

      for (String type: types){
        switch (type){
          case "t":
            booleanBuilder.or(board.title.contains(keyword));
            break;
          case "c":
            booleanBuilder.or(board.content.contains(keyword));
            break;
          case "w":
            booleanBuilder.or(board.writer.contains(keyword));
            break;

        }
      }
      query.where(booleanBuilder);

    }

    //bno > 0
    query.where(board.bno.gt(0L));

    JPQLQuery<BoardListReplyCountDTO> dtoQuery = query.select(Projections.bean(BoardListReplyCountDTO.class,
            board.bno,
            board.title,
            board.writer,
            board.regDate,
            reply.count().as("replyCount")
    ));

    this.getQuerydsl().applyPagination(pageable,dtoQuery);

    List<BoardListReplyCountDTO> dtoList = dtoQuery.fetch();

    Long count = dtoQuery.fetchCount();

    return new PageImpl<>(dtoList, pageable, count);

  }

  @Override
  public Page<BoardListAllDTO> searchWithAll(String[] types, String keyword, Pageable pageable) {

    QBoard board = QBoard.board;
    QReply reply = QReply.reply;

    JPQLQuery<Board> boardJPQLQuery = from(board);
    boardJPQLQuery.leftJoin(reply).on(reply.board.eq(board)); // left join

    if((types != null && types.length > 0) && keyword != null){
      BooleanBuilder booleanBuilder = new BooleanBuilder();
      for (String type :types){
        switch(type){
          case "t":
            booleanBuilder.or(board.title.contains(keyword));
            break;
          case "c":
            booleanBuilder.or(board.content.contains(keyword));
            break;
          case "w":
            booleanBuilder.or(board.writer.contains(keyword));
            break;
        }
      } //end for
      boardJPQLQuery.where(booleanBuilder);

    }



    boardJPQLQuery.groupBy(board);
    getQuerydsl().applyPagination(pageable, boardJPQLQuery); // paging

    JPQLQuery<Tuple> tupleJPQLQuery = boardJPQLQuery.select(board, reply.countDistinct());

    List<Tuple> tupleList = tupleJPQLQuery.fetch();

    List<BoardListAllDTO> dtoList = tupleList.stream().map(tuple -> {

      Board board1 = (Board) tuple.get(board);
      long replyCount = tuple.get(1,Long.class);

      BoardListAllDTO dto = BoardListAllDTO.builder()
              .bno(board1.getBno())
              .title(board1.getTitle())
              .writer(board1.getWriter())
              .regDate(board1.getRegDate())
              .replyCount(replyCount)
              .build();

      //BoardImage를 BoardImageDTO처리할 부분
      List<BoardImageDTO> imagesDTOS = board1.getImageSet().stream().sorted()
              .map(boardImage -> BoardImageDTO.builder()
                      .uuid(boardImage.getUuid())
                      .fileName(boardImage.getFileName())
                      .ord(boardImage.getOrd())
                      .build()
              ).collect(Collectors.toList());

      dto.setBoardImages(imagesDTOS);

      return dto;
    }).collect(Collectors.toList());

    long totalCount = boardJPQLQuery.fetchCount();

    return new PageImpl<>(dtoList, pageable, totalCount);
  }

  @Override
  public Page<BoardListAllDTO> listWithAll(PageRequestDTO pageRequestDTO) {
    return null;
  }
}
