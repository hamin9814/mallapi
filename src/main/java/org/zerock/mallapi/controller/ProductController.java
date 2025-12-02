package org.zerock.mallapi.controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.zerock.mallapi.dto.PageRequestDTO;
import org.zerock.mallapi.dto.PageResponseDTO;
import org.zerock.mallapi.dto.ProductDTO;
import org.zerock.mallapi.service.ProductService;
import org.zerock.mallapi.util.CustomFileUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import java.util.List;
import java.util.Map;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
//import org.springframework.web.bind.annotation.RequestParam;



@RestController
@RequiredArgsConstructor
@Log4j2
@RequestMapping("/api/products")
public class ProductController {
    private final ProductService productService;  // ProductService 객체 주입
    private final CustomFileUtil fileUtil;

    @GetMapping("/view/{fileName}")
    public ResponseEntity<Resource> viewFileGET(@PathVariable("fileName") String fileName) {
        return fileUtil.getFile(fileName);
    } 
    @PostMapping("/")
    public Map<String, Long> register(ProductDTO productDTO) {
        log.info("register: " + productDTO);
        List<MultipartFile> files = productDTO.getFiles();
        List<String> uploadFileNames = fileUtil.saveFiles(files);
        productDTO.setUploadFileNames(uploadFileNames);
        log.info(uploadFileNames);
        // 서비스 호출
        Long pno = productService.register(productDTO);
        return Map.of("result", pno);
    }   


    // @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")   // 임시로 권한 설정\
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/list")
    public PageResponseDTO<ProductDTO> list(PageRequestDTO pageRequestDTO) {
        log.info("list.............." + pageRequestDTO);
        return productService.getList(pageRequestDTO);
    }

        @GetMapping("/{pno}")
    public ProductDTO get(@PathVariable(name="pno") Long pno) {
        log.info("get: " + pno);
        return productService.get(pno);
    }

    @PutMapping("/{pno}")
    public Map<String, String> modify(@PathVariable(name="pno") Long pno, ProductDTO productDTO) {
        productDTO.setPno(pno);
        ProductDTO oldProductDTO = productService.get(pno);
        // 기존 파일 이름들
        List<String> oldFileNames = oldProductDTO.getUploadFileNames();
        // 새로 업로드해야 하는 파일들
        List<MultipartFile> files = productDTO.getFiles();
        // 새로 업로드되어서 만들어진 파일 이름들
        List<String> currentUploadFileNames = fileUtil.saveFiles(files);
        // 화면에서 변환없이 계속 유지된 파일들
        List<String> uploadedFileNames = productDTO.getUploadFileNames();
        // 유지된 파일들 + 새로 업로드된 파일들이 저장해야 하는 파일 목록
        if (currentUploadFileNames != null && currentUploadFileNames.size() > 0) {
            uploadedFileNames.addAll(currentUploadFileNames);
        }
        // 수정 작업
        productService.modify(productDTO);
        if (oldFileNames != null && oldFileNames.size() > 0) {
            // 지워야 하는 파일 목록 찾기
            // 예전 파일들 중에 지워져야 하는 파일 이름들
            List<String> removeFiles = oldFileNames.stream()
                .filter(fileName -> uploadedFileNames.indexOf(fileName)==-1)
                .toList();
            // 실제 파일 삭제
            fileUtil.deleteFile(removeFiles);
        }
        return Map.of("RESULT", "SUCCESS");
    }

        @DeleteMapping("/{pno}")
    public Map<String, String> remove(@PathVariable(name="pno") Long pno) {
        // 삭제해야 할 파일 알아내기
        List<String> oldFileNames = productService.get(pno).getUploadFileNames();
        productService.remove(pno);
        fileUtil.deleteFile(oldFileNames);
        return Map.of("RESULT", "SUCCESS");
    }


}

