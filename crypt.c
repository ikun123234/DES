#include <stdio.h>
#include <stdlib.h>
#include "time.h"
#include "JinZhiSwitch.h"
#include "Des.h"
#include "OpMode.h"

void showHelp()
{
    printf("___________________________________________\n");
    printf("|-h get help                              |\n");
    printf("|-p plain file                            |\n");
    printf("|-k key file                              |\n");
    printf("|-v init vector file                      |\n");
    printf("|-m encrypt or decrypt mode               |\n");
    printf("|       0 ecb encrypt                     |\n");
    printf("|       1 cbc encrypt                     |\n");
    printf("|       2 cfb encrypt                     |\n");
    printf("|       3 ofb encrypt                     |\n");
    printf("|       4 ecb decrypt                     |\n");
    printf("|       5 cbc decrypt                     |\n");
    printf("|       6 cfb decrypt                     |\n");
    printf("|       7 ofb decrypt                     |\n");
    printf("___________________________________________\n");
}
int main(int argc, char **argv)
{
    int cnt = 20;
    clock_t start_time;
    clock_t finish_time;
    float program_time;

    int mode = -1;
    int arg_require = 9;
    int is_need_initvec = 0;
    int h = 0;
    int flag = 1;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0)
        {
            strcpy(plaintextfile, argv[i + 1]);
            i++;
        }
        if (strcmp(argv[i], "-h") == 0)
        {
            h = 1;
            showHelp();
        }
        else if (strcmp(argv[i], "-k") == 0)
        {
            strcpy(keyfile, argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "-v") == 0)
        {
            strcpy(initvecfile, argv[i + 1]);
            arg_require++;
            is_need_initvec = 1;
            i++;
        }
        else if (strcmp(argv[i], "-m") == 0)
        {
            mode = atoi(argv[i + 1]);
            i++;
        }
        else if (strcmp(argv[i], "-c") == 0)
        {
            strcpy(cipherfile, argv[i + 1]);
            i++;
        }
    }
    if (argc == 1 || argc + is_need_initvec < arg_require)
    {
        if (h == 0)
        {
            printf("error\n");
        }

        flag = 0;
    }
    if (flag)
    {
        start_time = clock();
        for (size_t i = 0; i < 1; i++)
        {
            switch (mode)
            {
            case 0:
                des_ecb();
                break;
            case 1:
                des_cbc();
                break;
            case 2:
                des_cfb();
                break;
            case 3:
                des_ofb();
                break;
            case 4:
                dedes_ecb();
                break;
            case 5:
                dedes_cbc();
                break;
            case 6:
                dedes_cfb();
                break;
            case 7:
                dedes_ofb();
                break;
            default:
                break;
            }
        }
        finish_time = clock();
        program_time = (float)(finish_time - start_time);
        float rate = cnt / (program_time / 1000);
        printf("mode %d time is: %f ms\nthe rate is %f MBps\n", mode, program_time, rate);
    }

    return 0;
}