#include <stdio.h>
#include <stdint.h>

int main() {
// BigEndianValue를 uint32_t 자료형으로 선언 후 값을 저장  
    uint32_t BigEndianValue = 0x12345678; 

    FILE *fp; 
    
// bigendian_data 라는 이름의 바이너리 파일을 만들어 열고, 바이너리 모드로 쓸 것을 설정  
    fp = fopen("bigendian_data.bin", "wb"); 
// 선언한 파일에 uint32_t(4byte)크기만큼 BigEndianValue 변수에 있는 값을 저장 
    fwrite(&BigEndianValue, sizeof(uint32_t), 1, fp); 
    fclose(fp);  
}

