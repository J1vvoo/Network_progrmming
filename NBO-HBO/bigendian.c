#include <stdio.h>
#include <stdint.h>

int main() {
// BigEndianValue�� uint32_t �ڷ������� ���� �� ���� ����  
    uint32_t BigEndianValue = 0x12345678; 

    FILE *fp; 
    
// bigendian_data ��� �̸��� ���̳ʸ� ������ ����� ����, ���̳ʸ� ���� �� ���� ����  
    fp = fopen("bigendian_data.bin", "wb"); 
// ������ ���Ͽ� uint32_t(4byte)ũ�⸸ŭ BigEndianValue ������ �ִ� ���� ���� 
    fwrite(&BigEndianValue, sizeof(uint32_t), 1, fp); 
    fclose(fp);  
}

