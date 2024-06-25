#include "ctr_acpkm.h"
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "logs.h"
int get_rand(uint8_t* IV,int n)
{
    int FD=open("/dev/urandom",O_RDONLY);
    if(FD<0)
    {
        printf("FILE /dev/urandom didnt open\n");
        return -1;
    }
    if(read(FD,IV,n)<0)
    {
        printf("Can't read file\n");
        close(FD);
        return -2;
    }
    close(FD);
    return 0;
}

#define BUFFER_SIZE 4096

int get_h(int fd, uint8_t hash[32]) {
    SHA256_CTX context;
    SHA256_Init(&context);

    unsigned char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    while ((bytes_read = read(fd, buffer, BUFFER_SIZE)) > 0) {
        SHA256_Update(&context, buffer, bytes_read);
    }

    if (bytes_read < 0) {
        perror("Ошибка чтения файла");
        return -1;
    }

    SHA256_Final(hash, &context);

    return 0;
}

int compare_arrays(uint8_t array1[32],uint8_t array2[32], int size) {
    for (size_t i = 0; i < size; i++) {
        if (array1[i] != array2[i]) {
            return 0;
        }
    }
    return 1;
}

int alg(uint8_t* key,char* file)
{
    int FD=open(file,O_RDWR);
    if(FD<0)
    {
        printf("cant open your file\n");
        return -1;
    }

    uint8_t IV[16];
    uint8_t blk[16];
    uint8_t hash1[32];
    uint8_t hash2[32];
    get_LUT();
    if(file[0]=='E' && file[1]=='_')
    {
        int F=creat(file+2,0666);
        if(F<0)
        {
            printf("file didnt creat\n");
            return -4;
        }
        read(FD,IV,16);
        read(FD,hash1,32);
        int k;
        uint8_t f=0;
        while((k=read(FD,blk,16))>0)
        {
            if(f==0)
            {
                f=1;
            }
            else
            {
                ACPKM(key);
            }
            mode(blk,IV,key,k);
            write(F,blk,k);
        }
        close(F);
        close(FD);
        printf("DECRYPTION COMPLETED\n");
        log("Decryptiption completed");
        F=open(file+2,O_RDONLY);
        get_h(F,hash2);
        close(F);
        if(compare_arrays(hash1,hash2,32))
        {
            printf("Integrity completed\n");
        }
        else
        {
            printf("Integrity failed\n");
        }
        get_rand(key,32);
        log("key cleared");
        log("session end\n");
        return 1;
    }
    else
    {
        char* name=(char*)malloc(sizeof(char)*(2+strlen(file)));
        name[0]='E';
        name[1]='_';
        for(int i=0;i<strlen(file);i++)
        {
            name[2+i]=file[i];
        }
        name[strlen(file)+2]=0;
        int F=creat(name,0666);
        free(name);
        if(F<0)
        {
            printf("file didnt creat\n");
            return -5;
        }
        if(get_rand(IV,16)<0)
        {
            printf("error in get_iv()\n");
            return -6;
        }
        write(F,IV,16);
        get_h(FD,hash1);
        write(F,hash1,32);
        close(FD);
        FD=open(file,O_RDONLY);
        int k;
        uint8_t f=0;
        while((k = read(FD, blk, BLOCK_SIZE)) > 0)
        {
            if(f==0)
            {
                f=1;
            }
            else
            {
                ACPKM(key);
            }
            mode(blk,IV,key,k);
            write(F,blk,k);
        }
        printf("ENCRYPTION COMPLETED\n");
        log("encryption completed");
        get_rand(key,32);
        log("key cleared");
        log("end session\n");
        close(F);
        close(FD);
        return 2;
    }
    return 0;
}

