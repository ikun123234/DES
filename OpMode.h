#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include "JinZhiSwitch.h"
#include "Des.h"

#ifndef DESENCRYPT_OPMODE_H
#define DESENCRYPT_OPMODE_H
char strbuff[9];
char pkt_hex[17];
char pkt_bin[65];
char eb_hex[3];
char eb_bin[9];
char ebcipher_bin[9];
char ebcipher_hex[3];

char cipher_bin[65];
char cipher_hex[17];

void des_ecb()
{
    cipher_bin[64] = '\0';
    cipher_hex[16] = '\0';
    FILE *fp = NULL;
    fp = fopen(plaintextfile, "r");
    while (fgets(pkt_hex, 17, (FILE *)fp))
    {
        hex2bin(pkt_hex, pkt_bin);
        des(pkt_bin, cipher_bin);
        bin2hex(cipher_bin, cipher_hex);
        writeFile(cipherfile, cipher_hex);
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/                des of ECB finish          /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void dedes_ecb()
{
    cipher_bin[64] = '\0';
    cipher_hex[16] = '\0';

    FILE *fp = NULL;
    fp = fopen(cipherfile, "r");
    while (fgets(pkt_hex, 17, (FILE *)fp))
    {
        hex2bin(pkt_hex, pkt_bin);
        dedes(pkt_bin, cipher_bin);
        bin2hex(cipher_bin, cipher_hex);
        writeFile(plaintextfile, cipher_hex);
    }
    fclose(fp);

    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/          des of ECB finish                /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void des_cbc()
{
    cipher_bin[64] = '\0';
    cipher_hex[16] = '\0';
    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);
    FILE *fp = NULL;
    fp = fopen(plaintextfile, "r");
    char in[65];

    while (fgets(pkt_hex, 17, (FILE *)fp))
    {
        hex2bin(pkt_hex, pkt_bin);
        Xor(vecbin, pkt_bin, in, 64);
        in[64] = '\0';
        des(in, cipher_bin);
        strcpy(vecbin, cipher_bin);
        bin2hex(cipher_bin, cipher_hex);
        writeFile(cipherfile, cipher_hex);
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/             des of CBC finish             /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void dedes_cbc()
{
    cipher_bin[64] = '\0';
    cipher_hex[16] = '\0';

    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);

    FILE *fp = NULL;
    fp = fopen(cipherfile, "r");
    char in[65];

    while (fgets(cipher_hex, 17, (FILE *)fp))
    {
        hex2bin(cipher_hex, cipher_bin);
        dedes(cipher_bin, in);
        in[64] = '\0';
        Xor(vecbin, in, pkt_bin, 64);
        strcpy(vecbin, cipher_bin);
        bin2hex(pkt_bin, pkt_hex);
        writeFile(plaintextfile, pkt_hex);
    }

    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/           des of CBC finish               /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void des_cfb()
{
    ebcipher_bin[9] = '\0';
    ebcipher_hex[3] = '\0';
    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);
    FILE *fp = NULL;
    fp = fopen(plaintextfile, "r");
    char in[65];
    while (fgets(eb_hex, 3, (FILE *)fp))
    {
        hex2bin(eb_hex, eb_bin);
        in[64] = '\0';
        des(vecbin, in);
        Xor(in, eb_bin, ebcipher_bin, 8);
        bin2hex(ebcipher_bin, ebcipher_hex);
        writeFile(cipherfile, ebcipher_hex);

        char temp[65];
        temp[64] = '\0';
        strcpy(temp, vecbin);
        for (size_t i = 0; i < 56; i++)
        {
            vecbin[i] = temp[8 + i];
        }
        for (size_t i = 56; i < 64; i++)
        {
            vecbin[i] = ebcipher_bin[i - 56];
        }
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/            des of CFB finish              /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void dedes_cfb()
{
    eb_bin[9] = '\0';
    eb_hex[3] = '\0';
    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);
    FILE *fp = NULL;
    fp = fopen(cipherfile, "r");
    char in[65];
    while (fgets(ebcipher_hex, 3, (FILE *)fp))
    {
        hex2bin(ebcipher_hex, ebcipher_bin);
        in[64] = '\0';
        des(vecbin, in);
        Xor(in, ebcipher_bin, eb_bin, 8);
        bin2hex(eb_bin, eb_hex);
        writeFile(plaintextfile, eb_hex);

        char temp[65];
        temp[64] = '\0';
        strcpy(temp, vecbin);
        for (size_t i = 0; i < 56; i++)
        {
            vecbin[i] = temp[8 + i];
        }
        for (size_t i = 56; i < 64; i++)
        {
            vecbin[i] = ebcipher_bin[i - 56];
        }
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/          des of CFB finish                /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void des_ofb()
{
    cipher_bin[64] = '\0';
    cipher_hex[16] = '\0';
    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);
    FILE *fp = NULL;
    fp = fopen(plaintextfile, "r");
    char in[65];
    while (fgets(pkt_hex, 17, (FILE *)fp))
    {
        hex2bin(pkt_hex, pkt_bin);
        des(vecbin, in);
        in[64] = '\0';
        strcpy(vecbin, in);
        Xor(in, pkt_bin, cipher_bin, 64);
        bin2hex(cipher_bin, cipher_hex);
        writeFile(cipherfile, cipher_hex);
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/               des of OFB finish           /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}

void dedes_ofb()
{
    pkt_bin[64] = '\0';
    pkt_hex[16] = '\0';
    readInitVec(initvecfile);
    hex2bin(vechex, vecbin);
    FILE *fp = NULL;
    fp = fopen(cipherfile, "r");
    char in[65];
    while (fgets(cipher_hex, 17, (FILE *)fp))
    {
        hex2bin(cipher_hex, cipher_bin);
        des(vecbin, in);
        in[64] = '\0';
        strcpy(vecbin, in);
        Xor(in, cipher_bin, pkt_bin, 64);
        bin2hex(pkt_bin, pkt_hex);
        writeFile(plaintextfile, pkt_hex);
    }
    fclose(fp);
    printf("_____________________________________________\n");
    printf("/                                           /\n");
    printf("/              des of OFB finish            /\n");
    printf("/                                           /\n");
    printf("_____________________________________________\n");
}
#endif // DESENCRYPT_SWITCHTABLE_H