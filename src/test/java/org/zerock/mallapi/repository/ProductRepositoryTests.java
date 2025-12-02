package org.zerock.mallapi.repository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.annotation.Commit;
import org.zerock.mallapi.domain.Product;
import java.util.Optional;
import org.springframework.transaction.annotation.Transactional;
import lombok.extern.log4j.Log4j2;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;


@SpringBootTest
@Log4j2
public class ProductRepositoryTests {
    @Autowired
    private ProductRepository productRepository;

    @Test
    public void testInsert() {
        for (int i=0; i<10; i++) {
            Product product = Product.builder()
                .pname("상품" + i)
                .price(100*i)
                .pdesc("상품설명 " + i)
                .build();
            // 2개의 이미지 파일 추가
            product.addImageString(UUID.randomUUID().toString()+"_"+"IMAGE1.jpg");
            product.addImageString(UUID.randomUUID().toString()+"_"+"IMAGE2.jpg");
            productRepository.save(product);
            log.info("---------------------");
         }
    }
    @Transactional
    @Test
    public void testRead() {
        Long pno = 1L;
        Optional<Product> result = productRepository.findById(pno);
        Product product = result.orElseThrow();
        log.info(product);
        log.info(product.getImageList());
    }

    @Transactional
    @Test
    public void testRead2() {
        Long pno = 1L;
        Optional<Product> result = productRepository.selectOne(pno);
        Product product = result.orElseThrow();
        log.info(product);
        log.info(product.getImageList());
    }


    @Commit
    @Transactional
    @Test
    public void testDelete() {
        Long pno = 2L;
        productRepository.updateToDelete(pno, true);
    }
    @Test
    public void testUpdate() {
        Long pno = 10L;
        Product product = productRepository.selectOne(pno).get();
        
        product.changeName("10번 상품");
        product.changeDesc("10번 상품 설명입니다.");
        product.changePrice(5000);
        // 첨부 파일 수정
        product.clearList();
        product.addImageString(UUID.randomUUID().toString()+"_"+"NEW_IMAGE1.jpg");
        product.addImageString(UUID.randomUUID().toString()+"_"+"NEW_IMAGE2.jpg");
        product.addImageString(UUID.randomUUID().toString()+"_"+"NEW_IMAGE3.jpg");
        productRepository.save(product);
    }

    @Test
    public void testList() {
        // org.springframework.data.domain 패키지
        Pageable pageable = PageRequest.of(0, 10, Sort.by("pno").descending());
        Page<Object[]> result = productRepository.selectList(pageable);
        // java.util
        result.getContent().forEach(arr -> log.info(arr[0] + " : " + arr[1]));
    }

}
