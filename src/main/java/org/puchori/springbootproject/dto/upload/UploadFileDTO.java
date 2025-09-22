package org.puchori.springbootproject.dto.upload;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Data
public class UploadFileDTO {

  private List<MultipartFile> files;

}
