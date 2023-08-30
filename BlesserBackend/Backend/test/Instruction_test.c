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
        uint8_t *mut_values = CMD_FROM_BLESSER.mutation_values;
        char cmd_id = mut.cmd_id;
        char field_id = mut.field_id;

        int offset = 0;


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
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("io_capability: %u\n", _v);
                    break;
                }
                case 1:
                {
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("oob_data_flags: %u\n", _v);
                    break;
                }
                case 2:
                {
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("authreq: %u\n", _v);
                    break;
                }
                case 3:
                {
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("max_enc_key_size: %u\n", _v);
                    break;
                }
                case 4:
                {
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("initiator_key_distribution: %u\n", _v);
                    break;
                }
                case 5:
                {
                    uint8_t _v;
                    memcpy(&_v, &mut_values[offset], sizeof(_v));
                    offset += sizeof(_v);
                    printf("responder_key_distribution: %u\n", _v);
                    break;
                }
            }
        }
    }

}
