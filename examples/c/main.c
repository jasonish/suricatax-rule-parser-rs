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

    uintptr_t count;
    const CElement *elements = srp_parse_elements(input, &count);
    printf("Number of elements: %u\n", count);
    for (uintptr_t i = 0; i < count; i++) {
        CElement element = elements[i];
        printf("Tag: %u\n", element.tag);
        switch (element.tag) {
            case ELEMENT_TAG_ACTION: {
                const char *action = element.val;
                printf("- action: %s\n", action);
                break;
            }
            case ELEMENT_TAG_FLOWBITS: {
                const CFlowbits *flowbits = element.val;
                printf("- flowbits: command=%d\n", flowbits->command);
                for (int i = 0; i < flowbits->size; i++) {
                    printf("-- name: %s\n", flowbits->names[i]);
                }
                break;
            }
            default: {
                printf("Element tag %d not supported.\n", element.tag);
                break;
            }
        }
    }

    srp_free_elements(elements, count);

    return 0;
}
