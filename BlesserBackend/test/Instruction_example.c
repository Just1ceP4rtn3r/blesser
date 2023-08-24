#include"../Include/Instruction.h"
#include "stdio.h"


struct BlesserInstruction CMD_FROM_BLESSER;

int construct()
{

    CMD_FROM_BLESSER.mutation_count=1;
    CMD_FROM_BLESSER.mutations[0].cmd_id = 0x01;
    CMD_FROM_BLESSER.mutations[0].field_id = 0;
    CMD_FROM_BLESSER.mutation_values[0] = 0xff;

    return 0;
}

