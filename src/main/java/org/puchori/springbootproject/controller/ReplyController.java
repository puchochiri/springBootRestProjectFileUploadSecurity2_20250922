package org.puchori.springbootproject.controller;


import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.puchori.springbootproject.dto.PageRequestDTO;
import org.puchori.springbootproject.dto.PageResponseDTO;
import org.puchori.springbootproject.dto.ReplyDTO;
import org.puchori.springbootproject.service.ReplyService;
import org.springframework.http.MediaType;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/replies")
@Log4j2
@Tag(name="Replies API", description = "댓글 관련 API")
@RequiredArgsConstructor // 의존성 주입을 위함
public class ReplyController {

  private final ReplyService replyService;
  @Operation(
      summary = "Replies Post",
      description = "POST 방식으로 댓글 등록"
  )
  @PostMapping(value = "/", consumes = MediaType.APPLICATION_JSON_VALUE)
  public Map<String,Long> register(@Valid @RequestBody ReplyDTO replyDTO, BindingResult bindingResult) throws BindException{

    log.info(replyDTO);

    if(bindingResult.hasErrors()) {
      throw new BindException(bindingResult);
    }

    Map<String, Long> resultMap = new HashMap<>();

    Long rno = replyService.register(replyDTO);

    resultMap.put("rno",rno);


    return resultMap;
  }

  @Operation(
          summary = "Replies Post",
          description = "POST 방식으로 댓글 등록"
  )
  @GetMapping(value = "/list/{bno}")
  public PageResponseDTO<ReplyDTO> getList(@PathVariable("bno") Long bno, PageRequestDTO pageRequestDTO){

    PageResponseDTO<ReplyDTO> responseDTO = replyService.getListOfBoard(bno, pageRequestDTO);

    return responseDTO;

  }

  @Operation(
          summary = "Read Reply",
          description = "GET 방식으로 특정 댓글 조회"
  )
  @GetMapping("/{rno}")
  public ReplyDTO getReplyDTO(@PathVariable("rno") Long rno){

    ReplyDTO replyDTO = replyService.read(rno);

    return replyDTO;

  }


  @Operation(
          summary = "Delete Reply"
          ,description = "DELETE 방식으로 특정 댓글 삭제"
  )
  @DeleteMapping("/{rno}")
  public Map<String,Long> remove(@PathVariable("rno") Long rno){
    replyService.remove(rno);

    Map<String , Long> resultMap = new HashMap<>();

    resultMap.put("rno",rno);

    return resultMap;
  }

  @Operation(
          summary = "Modify Reply"
          ,description = "PUT 방식으로 특정 댓글 수정"
  )
  @PutMapping(value="/{rno}", consumes = MediaType.APPLICATION_JSON_VALUE)
  public Map<String,Long> modify(@PathVariable("rno") Long rno, @RequestBody ReplyDTO replyDTO){
    replyDTO.setRno(rno);
    replyService.modify(replyDTO);
    Map<String, Long> resultMap = new HashMap<>();

    resultMap.put("rno",rno);

    return resultMap;


  }





}
