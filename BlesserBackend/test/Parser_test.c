#include<stdio.h>
#include"../Include/Instruction.h"

struct BlesserInstruction CMD_FROM_BLESSER;

int parse(struct BlesserInstruction *instruction, char *recv, int len){
    int offset = 0;
    instruction->mutation_count = 0;
    short mapper[16][6]={
        {},
        {1, 1, 1, 1, 1, 1},
        {1, 1, 1, 1, 1, 1},
        {16},
        {16},
        {1},
        {16},
        {2, 8},
        {16},
        {1, 6},
        {16},
        {1},
        {32, 32},
        {16},
        {1},
        {}
    };
    while (offset < len) {
        instruction->mutations[instruction->mutation_count].cmd_id = *(char *)(recv+offset);
        instruction->mutations[instruction->mutation_count].field_id = *(char *)(recv+offset+1);
        int value_size =  mapper[instruction->mutations[instruction->mutation_count].cmd_id][instruction->mutations[instruction->mutation_count].field_id];
        memcpy(instruction->mutations[instruction->mutation_count].mutation_values, recv+offset+2,value_size);


        printf("%u, %u, %x\n", instruction->mutations[instruction->mutation_count].cmd_id,instruction->mutations[instruction->mutation_count].field_id, *instruction->mutations[instruction->mutation_count].mutation_values);
        instruction->mutation_count++;
        offset += 1+1+value_size;
    }
    return 0;
}


int main()
{
    char test[] = {0x01, 0x02, 0xaa,0x01, 0x00, 0xff, 0x01, 0x01, 0xef};
    parse(&CMD_FROM_BLESSER, test, sizeof(test));

    return 0;
}
