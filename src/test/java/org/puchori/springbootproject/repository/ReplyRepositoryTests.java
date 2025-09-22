package org.puchori.springbootproject.repository;

import jakarta.transaction.Transactional;
import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.domain.Reply;
import org.puchori.springbootproject.dto.BoardDTO;
import org.puchori.springbootproject.dto.BoardListReplyCountDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;
import java.util.stream.IntStream;

@SpringBootTest
@Log4j2
public class ReplyRepositoryTests {

  @Autowired
  private ReplyRepository replyRepository;

  @Autowired
  private BoardRepository boardRepository;

  @Test
  public void testInsert() {

    // 실제 DB에 있는 bno
    Long bno = 2509L;

    Board board = Board.builder().bno(bno).build();

    Reply reply = Reply.builder()
            .board(board)
            .replyText("댓글.....")
            .replyer("replyer1")
            .build();

    replyRepository.save(reply);



  }

    @Test
  public void testRepltDummyInsert() {

    List<Board> result  =  boardRepository.findAll();

      for (Board board : result) {
        IntStream.rangeClosed(1,30).forEach(i -> {
                  Reply reply = Reply.builder()
                .board(board)
                .replyer("댓글......" + i)
                .replyText("replyer" + i)
                .build();

            Reply savedata = replyRepository.save(reply);

        });

      }




  }


  @Transactional
  @Test
  public void testBoardReplies(){
    Long bno = 99L;

    Pageable pageable = PageRequest.of(0,10, Sort.by("rno").descending());

    Page<Reply> result = replyRepository.listOfBoard(bno,pageable);

    result.getContent().forEach(reply -> {
      log.info(reply);
    });
  }




}
