#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "rules.h"

int main(int argc, char **argv)
{
    char *input =
        "alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"ET MALWARE "
        "Win32.Kovter Client CnC Traffic\"; flow:established,to_server; "
        "dsize:4<>256; content:!\"HTTP\"; content:\"|00 00 00|\"; offset:1; "
        "depth:3; pcre:\"/^[\\x11\\x21-\\x26\\x41\\x45\\x70-\\x79]/R\"; "
        "content:!\"|00 00|\"; distance:0; "
        "byte_jump:1,0,from_beginning,post_offset 3; isdataat:!2,relative; "
        "pcre:!\"/\\x00$/\"; "
        "flowbits:set,foo; "
        "reference:url,symantec.com/connect/blogs/"
        "kovter-malware-learns-poweliks-persistent-fileless-registry-update; "
        "classtype:command-and-control; sid:2022861; rev:1; "
        "metadata:created_at 2016_06_06, former_category MALWARE, updated_at "
        "2016_06_06;)";

    CRule *rule = parse_rule(input);
    printf("rule: %p\n", rule);
    printf("- action: %s\n", rule->action);
    printf("- proto: %s\n", rule->proto);

    for (int i = 0; i < rule->option_count; i++) {
        const CRuleOption *option = &rule->options[i];
        switch (option->option_type) {
            case C_OPTION_TYPE_BYTE_JUMP: {
                const ByteJumpOption *byte_jump = option->option;
                printf("- byte_jump:\n");
                printf("-- count: %u\n", byte_jump->count);
                printf("-- offset: %u\n", byte_jump->offset);
                printf("-- from_beginning: %d\n", byte_jump->from_beginning);
                break;
            }
            case C_OPTION_TYPE_METADATA: {
                const char *metadata = option->option;
                printf("- metadata: %s\n", metadata);
                break;
            }
            case C_OPTION_TYPE_OFFSET: {
                const uint64_t *offset = option->option;
                printf("- offset: %"PRIu64"\n", *offset);
                break;
            }
            case C_OPTION_TYPE_FLOWBITS: {
                const CFlowbits *flowbits = option->option;
                printf("- flowbits: %d\n", flowbits->command);
                for (int i = 0; i < flowbits->size; i++) {
                    printf("-- flowbit name: %s\n", flowbits->names[i]);
                }
                break;
            }
            default:
                printf("warning: don't know how to handle option: %d\n",
                    option->option_type);
                break;
        }
    }

    rule_free(rule);

    return 0;
}
