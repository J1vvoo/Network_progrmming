#include <stdio.h>
#include <stdint.h>

// 4byte 크기(uint32_t)의 BigEndian을 LittleEndian으로 변환해주는 change 함수 선언 
uint32_t change(uint32_t value) { 

// 비트연산을 통해 LittleEndian으로 변환  
		return (value >> 24) |   
           ((value >> 8 ) & 0x0000FF00) |   
           ((value << 8) & 0x00FF0000) |   
           (value << 24);   
	}   
	
int main(int argc, char *argv[]) {
// 인자가 제대로 받아지지 않았을 경우  
	if (argc != 3) {
		printf("Usage : %s <입력 파일> <출력 파일>\n", argv[0]);
	} 
	
// 파일 변수 선언 후 바이너리 모드로 열어 inputfile에 저장  
	FILE *fp; 
	fp = fopen(inputfile, "rb"); 

// BigEndian 변수를 uint32_t 자료형으로 선언 
	uint32_t BigEndian;  
// 선언한 파일을 uint32_t(4byte)씩 한 블록 읽어와 BigEndian 변수에 저장 
	fread(&BigEndian, sizeof(uint32_t), 1, fp);   
	fclose(fp);  
	
// LittleEndian 변수를 uint32_t 자료형으로 선언 후 change 함수를 통해 변환된 Big Endian을 저장
	uint32_t LittleEndian = change(BigEndian);   
	
// 파일 변수 선언 후 outputfile에 바이너리 모드로 쓸 것을 설정  
	fp = fopen(outputfile, "wb"); 
// 선언한 파일에 uint32_t(4byte)크기만큼 LittleEndian 변수에 있는 값을 저장 
	fwrite(&LittleEndian, sizeof(uint32_t), 1, fp); 
	fclose(fp); 
}

