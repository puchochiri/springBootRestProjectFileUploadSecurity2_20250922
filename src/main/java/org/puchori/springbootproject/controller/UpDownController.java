package org.puchori.springbootproject.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.extern.log4j.Log4j2;
import net.coobird.thumbnailator.Thumbnailator;
import org.puchori.springbootproject.dto.upload.UploadFileDTO;
import org.puchori.springbootproject.dto.upload.UploadResultDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@RestController
@Log4j2
public class UpDownController {

  @Value("${org.puchori.upload.path}") // import 시에 springframework으로 시작하는 value
  private String uploadPath;

  @Operation(
          summary = "Upload Post"
          ,description = "Post 방식으로 파일 등록"
  )
  @PostMapping(value="/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  public List<UploadResultDTO> upload(UploadFileDTO uploadFileDTO){
    log.info(uploadFileDTO);

    if(uploadFileDTO.getFiles() != null) {

      final List<UploadResultDTO> list = new ArrayList<>();
      uploadFileDTO.getFiles().forEach(multipartFile -> {

        String originalName = multipartFile.getOriginalFilename();
        log.info(originalName);

        String uuid = UUID.randomUUID().toString();
        Path savePath = Paths.get(uploadPath, uuid + "_" + originalName);

        boolean image = false;

        try{
          multipartFile.transferTo(savePath);

          String contentType = Files.probeContentType(savePath);
          //이미지 파일의 종류라면
          if(contentType != null && contentType.startsWith("image")){
            image = true;

            File thumbFile = new File(uploadPath, "s_" + uuid + "_" + originalName);

            Thumbnailator.createThumbnail(savePath.toFile(), thumbFile, 200,200);
          }

        } catch(IOException e) {
          e.printStackTrace();
        }

        list.add(UploadResultDTO.builder()
                .uuid(uuid)
                .fileName(originalName)
                .img(image)
                .build()
        );
      }); //end each

      return list;
    } // end if

    return null;

  }

  @Operation(
          summary = "view 파일"
          ,description = "GET방식으로 첨부파일 조회"
  )
  @GetMapping("/view/{fileName}")
  public ResponseEntity<Resource> viewFileGet(@PathVariable String fileName){

    Resource resource = new FileSystemResource(uploadPath + File.separator + fileName);

    String resourceName = resource.getFilename();
    HttpHeaders headers = new HttpHeaders();

    try {
      // MIME 타입 지정
      String contentType = Files.probeContentType(resource.getFile().toPath());

      if(contentType == null){
        contentType = "application/octet-stream";
      }


      //섬네일이 존재하면 보여주기
      if(contentType.startsWith("image")){
        headers.add(HttpHeaders.CONTENT_TYPE, contentType);
      } else {
      //다운로드 되도록 설정(inline
        headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" +resourceName + "\"");
      }




    } catch(Exception e) {
      return ResponseEntity.internalServerError().build();
    }

    return ResponseEntity.ok().headers(headers).body(resource);


  }

  @Operation(
          summary = "remove 파일"
          ,description = "DELETE 방식으로 파일 삭제"
  )
  @DeleteMapping("/remove/{fileName}")
  public Map<String,Boolean> removeFile(@PathVariable String fileName){

    Resource resource = new FileSystemResource(uploadPath + File.separator + fileName);

    String resourceName = resource.getFilename();

    Map<String, Boolean> resultMap = new HashMap<>();

    boolean removed = false;

    try {

      String  contentType = Files.probeContentType(resource.getFile().toPath());
      removed = resource.getFile().delete();

      //섬네일이 존재한다면
      if(contentType.startsWith("image")){
        File thumbnailFile = new File(uploadPath + File.separator + "s_" + fileName);

        thumbnailFile.delete();
      }

    } catch(Exception e) {
      log.error(e.getMessage());
    }

    resultMap.put("result",removed);

    return resultMap;




  }



}
