#include <stdio.h>
#include <stdint.h>

// 4byte ũ��(uint32_t)�� BigEndian�� LittleEndian���� ��ȯ���ִ� change �Լ� ���� 
uint32_t change(uint32_t value) { 

// ��Ʈ������ ���� LittleEndian���� ��ȯ  
		return (value >> 24) |   
           ((value >> 8 ) & 0x0000FF00) |   
           ((value << 8) & 0x00FF0000) |   
           (value << 24);   
	}   
	
int main(int argc, char *argv[]) {
// ���ڰ� ����� �޾����� �ʾ��� ���  
	if (argc != 3) {
		printf("Usage : %s <�Է� ����> <��� ����>\n", argv[0]);
	} 
	
// ���� ���� ���� �� ���̳ʸ� ���� ���� inputfile�� ����  
	FILE *fp; 
	fp = fopen(inputfile, "rb"); 

// BigEndian ������ uint32_t �ڷ������� ���� 
	uint32_t BigEndian;  
// ������ ������ uint32_t(4byte)�� �� ��� �о�� BigEndian ������ ���� 
	fread(&BigEndian, sizeof(uint32_t), 1, fp);   
	fclose(fp);  
	
// LittleEndian ������ uint32_t �ڷ������� ���� �� change �Լ��� ���� ��ȯ�� Big Endian�� ����
	uint32_t LittleEndian = change(BigEndian);   
	
// ���� ���� ���� �� outputfile�� ���̳ʸ� ���� �� ���� ����  
	fp = fopen(outputfile, "wb"); 
// ������ ���Ͽ� uint32_t(4byte)ũ�⸸ŭ LittleEndian ������ �ִ� ���� ���� 
	fwrite(&LittleEndian, sizeof(uint32_t), 1, fp); 
	fclose(fp); 
}

