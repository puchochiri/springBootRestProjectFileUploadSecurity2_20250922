package org.puchori.springbootproject.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import lombok.extern.log4j.Log4j2;
import org.puchori.springbootproject.dto.*;
import org.puchori.springbootproject.service.BoardService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.File;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.util.List;

@Controller
@RequestMapping("/board")
@Log4j2
@RequiredArgsConstructor
public class BoardController {

  @Value("${org.puchori.upload.path}") // import 시에 springframwork으로 시작하는 value
  private String uploadPath;

  private final BoardService boardService;



  @GetMapping("/list")
  public void list(PageRequestDTO pageRequestDTO, Model model){

    //PageResponseDTO<BoardDTO> responseDTO = boardService.list(pageRequestDTO);

    //PageResponseDTO<BoardListReplyCountDTO> responseDTO = boardService.listWithReplyCount(pageRequestDTO);

    PageResponseDTO<BoardListAllDTO> responseDTO = boardService.listWithAll(pageRequestDTO);

    log.info(responseDTO);

    model.addAttribute("responseDTO",responseDTO);



  }

  @PreAuthorize("hasRole('USER')")
  @GetMapping("/register")
  public void registerGET(){
    log.info("board Get register.......");

  }

  @PostMapping("/register")
  public String registerPost(@Valid BoardDTO boardDTO, BindingResult bindingResult, RedirectAttributes redirectAttributes){

    log.info("board POST register.......");

    if(bindingResult.hasErrors()) {
      log.info("has erros............");
      redirectAttributes.addFlashAttribute("errors",bindingResult.getAllErrors());

      return "redirect:/board/register";


    }

    log.info(boardDTO);

    Long bno = boardService.register(boardDTO);

    redirectAttributes.addFlashAttribute("result",bno);

    return "redirect:/board/list";

  }
  @PreAuthorize("isAuthenticated()")
  @GetMapping({"/read", "/modify"})
  public void read(Long bno, PageRequestDTO pageRequestDTO, Model model){
    BoardDTO boardDTO = boardService.readOne(bno);

    log.info(boardDTO);

    model.addAttribute("dto",boardDTO);
  }

  @PreAuthorize("principal.username == #boardDTO.writer")
  @PostMapping("/modify")
  public String modify(PageRequestDTO pageRequestDTO,
                       @Valid BoardDTO boardDTO,
                       BindingResult bindingResult,
                       RedirectAttributes redirectAttributes) {
    log.info("board modify post......" + boardDTO);

    String link = pageRequestDTO.getLink();
    if(bindingResult.hasErrors()){
      log.info("has errors.......");



      redirectAttributes.addFlashAttribute("errors",bindingResult.getAllErrors());

      redirectAttributes.addAttribute("bno",boardDTO.getBno());

      return "redirect:/board/modify?" + link;
    }

    boardService.modify(boardDTO);

    redirectAttributes.addFlashAttribute("result","modified");

    redirectAttributes.addAttribute("bno",boardDTO.getBno());

    return "redirect:/board/read?" + link;

  }

  @PreAuthorize("principal.username == #boardDTO.writer")
  @PostMapping("remove")
  public String remove(BoardDTO boardDTO,PageRequestDTO pageRequestDTO, RedirectAttributes redirectAttributes){
    Long bno = boardDTO.getBno();
    log.info("remove post.." + bno);

    boardService.remove(bno);

    //게시물에 데이터베이스상에서 삭제되었다면 첨부파일 삭제
    log.info(boardDTO.getFileNames());
    List<String> fileNames = boardDTO.getFileNames();
    if(fileNames != null && fileNames.size() > 0){
      removeFiles(fileNames);
    }

    String link = pageRequestDTO.getLink();

    redirectAttributes.addFlashAttribute("result","removed");

    return "redirect:/board/list?" + link;
  }

  public void removeFiles(List<String> files){
    for (String fileName:files){
      Resource resource = new FileSystemResource(uploadPath + File.separator + fileName);

      String resourceName = resource.getFilename();

      try {
        String contentType = Files.probeContentType(resource.getFile().toPath());

        resource.getFile().delete();

        //섬네일이 존재한다면
        if(contentType.startsWith("image")){
          File thumbnailFile = new File(uploadPath + File.separator + "s_" + fileName);

          thumbnailFile.delete();
        }


      } catch (Exception e) {
        log.error(e.getMessage());

      }



    }
  }


}
