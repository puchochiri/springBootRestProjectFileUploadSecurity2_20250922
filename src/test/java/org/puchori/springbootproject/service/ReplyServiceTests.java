package org.puchori.springbootproject.service;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.puchori.springbootproject.domain.Board;
import org.puchori.springbootproject.dto.ReplyDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.stream.IntStream;

@SpringBootTest
@Log4j2
public class ReplyServiceTests {

  @Autowired
  private ReplyService replyService;

  @Test
  public void testRegister(){

    ReplyDTO replyDTO = ReplyDTO.builder()
            .replyText("ReplyDTO Text")
            .replyer("replyer")
            .bno(2508L)
            .build();

    log.info(replyService.register(replyDTO));



  }

  @Test
  public void testReplyInsert() {
    IntStream.rangeClosed(200,1000).forEach(i -> {
      ReplyDTO replyDTO = ReplyDTO.builder()
            .replyText("ReplyDTO Text" + i)
            .replyer("replyer")
            .bno(2508L)
            .build();

    log.info(replyService.register(replyDTO));

    });

  }

}
