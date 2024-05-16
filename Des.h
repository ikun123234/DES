#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include "ZhiHuanTable.h"
#include "JinZhiSwitch.h"

#ifndef DESENCRYPT_DES_H
#define DESENCRYPT_DES_H

char keyfile[50];
char cipherfile[50];
char plaintextfile[50];
char initvecfile[50];

char key_buf[9];
char key_hex[17];
char key_bin[65];

char c[29];
char d[29];
char cd[57];

char vechex[17];
char vecbin[65];

void readKey(char *filename)
{
    FILE *fp = NULL;
    fp = fopen(filename, "r");
    fgets(key_hex, 17, (FILE *)fp);
    key_hex[16] = '\0';
    fclose(fp);
}

void readInitVec(char *filename)
{
    FILE *fp = NULL;
    fp = fopen(filename, "r");
    fgets(vechex, 17, (FILE *)fp);
    vechex[16] = '\0';
    fclose(fp);
}

void strMerge(char *str1, char *str2, char *res)
{
    int len = strlen(str1);
    for (size_t i = 0; i < len; i++)
    {
        res[i] = str1[i];
        res[len + i] = str2[i];
    }
}

void initSwitch(char *m)
{
    char temp[64];
    strcpy(temp, m);
    for (int i = 0; i < 64; i++)
    {
        m[i] = temp[ip_table[i] - 1];
    }
}

void reIPSwitch(char *m)
{
    char temp[65];
    strcpy(temp, m);
    for (int i = 0; i < 64; i++)
    {
        m[i] = temp[ipre_table[i] - 1];
    }
}

void sSwitch(char *str, char *end)
{
    char s[7];
    s[6] = '\0';
    char hang[3];
    hang[2] = '\0';
    int h;
    char lie[5];
    lie[4] = '\0';
    int l;
    int afters[8];
    for (size_t i = 0; i < 8; i++)
    {
        for (size_t j = 0; j < 6; j++)
        {
            s[j] = str[6 * i + j];
        }
        hang[0] = s[0];
        hang[1] = s[5];
        for (size_t k = 0; k < 4; k++)
        {
            lie[k] = s[1 + k];
        }

        h = bin2dec(hang);
        l = bin2dec(lie);

        afters[i] = s_table[i][h][l];
    }
    char buf[5];
    buf[4] = '\0';
    for (size_t i = 0; i < 8; i++)
    {
        itoa(dec2bin(afters[i]), buf, 10);
        int lenofbuf = strlen(buf);
        switch (lenofbuf)
        {
        case 4:
            break;
        case 3:
            buf[3] = buf[2];
            buf[2] = buf[1];
            buf[1] = buf[0];
            buf[0] = '0';
            break;
        case 2:
            buf[2] = buf[0];
            buf[3] = buf[1];
            buf[0] = '0';
            buf[1] = '0';
            break;
        case 1:
            buf[3] = buf[0];
            buf[0] = '0';
            buf[1] = '0';
            buf[2] = '0';
            break;
        default:
            break;
        }
        for (size_t j = 0; j < 4; j++)
        {
            end[4 * i + j] = buf[j];
        }
    }
}

void extend(char *r, char *e)
{
    for (int i = 0; i < 48; i++)
    {
        e[i] = r[e_table[i] - 1];
    }
}

void pSwitch(char *start, char *end)
{
    for (size_t i = 0; i < 32; i++)
    {
        end[i] = start[p_table[i] - 1];
    }
}

void lsSwitch(char *str, int round)
{
    int times = ls_table[round - 1];
    char temp[28];
    strcpy(temp, str);
    for (size_t i = 0; i < 28; i++)
    {
        str[i] = temp[(i + times) % 28];
    }
}

void Xor(char *a, char *b, char *res, int len)
{
    char ret[len + 1];
    ret[len] = '\0';
    for (size_t i = 0; i < len; i++)
    {
        if (a[i] == b[i])
        {
            ret[i] = '0';
        }
        else
        {
            ret[i] = '1';
        }
    }
    strcpy(res, ret);
}

void keyGen(char *key, int round, char *afterkey)
{
    if (round == 1)
    {
        char temp[65];
        strcpy(temp, key);
        for (size_t i = 0; i < 56; i++)
        {
            cd[i] = temp[pc1_table[i] - 1];
        }
        cd[56] = '\0';
        c[28] = '\0';
        d[28] = '\0';
    }

    for (size_t i = 0; i < 28; i++)
    {
        c[i] = cd[i];
        d[i] = cd[28 + i];
    }

    lsSwitch(c, round);
    lsSwitch(d, round);
    c[28] = '\0';
    d[28] = '\0';
    strMerge(c, d, cd);
    cd[56] = '\0';
    for (size_t i = 0; i < 48; i++)
    {
        afterkey[i] = cd[pc2_table[i] - 1];
    }
}

void des(char *in, char *out)
{
    int n = 2022141530150 % 16;
    readKey(keyfile);
    // 密钥转换成二进制
    hex2bin(key_hex, key_bin);
    key_bin[64] = '\0';

    char temp[65];
    strcpy(temp, in);
    temp[64] = '\0';

    // 进行ip置换
    initSwitch(temp);
    char l[33];
    char r[33];
    // 将输入分为左右两部分
    for (size_t i = 0; i < 32; i++)
    {
        l[i] = temp[i];
        r[i] = temp[32 + i];
    }

    l[32] = '\0';
    r[32] = '\0';

    for (size_t round = 1; round < 17; round++)
    {
        char er[49];
        er[48] = '\0';
        extend(r, er);

        char key1[49];
        key1[48] = '\0';
        keyGen(key_bin, round, key1);
        strcpy(key_bin, key1);

        char res[49];
        res[48] = '\0';
        Xor(key_bin, er, res, 48);

        char afters[64];
        sSwitch(res, afters);

        char afterp[33];
        afterp[32] = '\0';
        pSwitch(afters, afterp);

        char r0[33];
        r0[32] = '\0';
        Xor(l, afterp, r0, 32);
        strMerge(r, r0, temp);
         if (round - 1 == n)
         {
             printf("round %d des: %s\n", round - 1, temp);
         }
        strcpy(l, r);
        strcpy(r, r0);
    }
    strMerge(r, l, temp);
    reIPSwitch(temp);
    strcpy(out, temp);
}

void dedes(char *in, char *out)
{
    int n = 2022141530150 % 16;
    char temp[65];
    strcpy(temp, in);
    temp[64] = '\0';

    char keys[16][68];
    readKey(keyfile);
    hex2bin(key_hex, key_bin);
    initSwitch(temp);
    char l[33];
    char r[33];
    for (size_t i = 0; i < 32; i++)
    {
        l[i] = temp[i];
        r[i] = temp[32 + i];
    }

    l[32] = '\0';
    r[32] = '\0';
    for (size_t i = 0; i < 16; i++)
    {
        keyGen(key_bin, i + 1, keys[i]);
        keys[i][48] = '\0';
    }
    // 解密
    for (size_t round = 1; round < 17; round++)
    {

        char er[49];
        er[48] = '\0';
        extend(r, er);
        char res[49];
        res[48] = '\0';
        Xor(keys[16 - round], er, res, 48);
        char afters[64];
        sSwitch(res, afters);
        char afterp[33];
        afterp[32] = '\0';
        pSwitch(afters, afterp);
        char r0[33];
        r0[32] = '\0';
        Xor(l, afterp, r0, 32);
        strMerge(r, r0, temp);
         if (round - 1 == n)
         {
             printf("round %d des: %s\n", round - 1, temp);
         }
        strcpy(l, r);
        strcpy(r, r0);
    }
    strMerge(r, l, temp);
    reIPSwitch(temp);
    strcpy(out, temp);
}

#endif // DESENCRYPT_DES_H