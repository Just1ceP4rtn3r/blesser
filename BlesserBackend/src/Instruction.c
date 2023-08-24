#include "Instruction.h"

/*
* func parse()
* 参数: struct Instruction *instruction, uint8_t *recv, int len
*       Instruction类型结构体的指针,      uart收到的数据的指针, uart收到的数据的长度 
* 返回值: 函数执行完后返回0
*/
int parse(struct BlesserInstruction *instruction, uint8_t *recv, int len){
    instruction->mutation_count = recv[0];
    int i = 0;
    int j = 1;
    while(i < instruction->mutation_count && j < len){
        instruction->mutations[i].cmd_id = recv[j++];
        instruction->mutations[i++].field_id = recv[j++];
    }
    for(i=0; j < len; i++, j++){
        instruction->mutation_values[i] = recv[j];
    }
    return 0;
}