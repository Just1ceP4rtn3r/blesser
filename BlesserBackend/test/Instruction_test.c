#include<stdio.h>
#include"../Include/Instruction.h"


extern struct BlesserInstruction CMD_FROM_BLESSER;

int construct();
void main()
{
    construct();
    for(int i =0 ; i< CMD_FROM_BLESSER.mutation_count; i++)
    {
        struct mutation mut = CMD_FROM_BLESSER.mutations[i];

        char cmd_id = mut.cmd_id;
        char field_id = mut.field_id;

        // "smp_pairing_req": [
        //     "io_capability",
        //     "oob_data_flags",
        //     "authreq",
        //     "max_enc_key_size",
        //     "initiator_key_distribution",
        //     "responder_key_distribution"
        // ],  # 0x01
        if(cmd_id == 0x01)
        {
            switch(field_id)
            {
                case 0:
                {
                    printf("io_capability: \n");
                    break;
                }
                case 1:
                {
                    printf("oob_data_flags: \n");
                    break;
                }
                case 2:
                {
                    printf("authreq: \n");
                    break;
                }
                case 3:
                {
                    printf("max_enc_key_size: \n");
                    break;
                }
                case 4:
                {
                    printf("initiator_key_distribution: \n");
                    break;
                }
                case 5:
                {
                    printf("responder_key_distribution: \n");
                    break;
                }
            }
        }


    }

}
