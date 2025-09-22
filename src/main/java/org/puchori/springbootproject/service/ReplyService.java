package org.puchori.springbootproject.service;

import org.puchori.springbootproject.dto.PageRequestDTO;
import org.puchori.springbootproject.dto.PageResponseDTO;
import org.puchori.springbootproject.dto.ReplyDTO;

public interface ReplyService {

  Long register(ReplyDTO replyDTO);

  ReplyDTO read(Long rno);

  void modify(ReplyDTO replyDTO);

  void remove(Long rno);

  PageResponseDTO<ReplyDTO> getListOfBoard(Long bno, PageRequestDTO pageRequestDTO);

}
