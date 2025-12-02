package org.zerock.mallapi.service;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.zerock.mallapi.dto.PageRequestDTO;
import org.zerock.mallapi.dto.PageResponseDTO;
import org.zerock.mallapi.dto.ProductDTO;

import lombok.extern.log4j.Log4j2;

@SpringBootTest
@Log4j2
public class ProductServiceTests {
    @Autowired
    private ProductService productService;

    @Test
    public void testGetList() {
        // default 1 page, 10 size
        PageRequestDTO pageRequestDTO = PageRequestDTO.builder().build();
        PageResponseDTO<ProductDTO> result = productService.getList(pageRequestDTO);
        result.getDtoList().forEach(productDTO -> log.info(productDTO));
    }
    @Test
    public void testRegister() {
        ProductDTO productDTO = ProductDTO.builder()
            .pname("새로운 상품")
            .price(1000)
            .pdesc("신규 추가 상품입니다.")
            .build();
        // uuid_파일명 형태로 이미지 파일 2개 추가
        productDTO.setUploadFileNames(
            java.util.List.of(
                UUID.randomUUID().toString() + "_" + "Test1.jpg",
                UUID.randomUUID().toString() + "_" + "Test2.jpg"
            )
        );
        productService.register(productDTO);
    }
    @Test
    public void testRead() {
        Long pno = 12L;
        ProductDTO productDTO = productService.get(pno);
        log.info(productDTO);
        log.info(productDTO.getUploadFileNames());
    }


}
