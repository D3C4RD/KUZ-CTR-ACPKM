#include "auth.h"
#include "encrypter.h"
#include "time_check.h"
//#include "cel.h"
int gen_keyfile()
{
    int F=creat("key",0666);
    if(F<0)
    {
        printf("key didnt creat\n");
        return 0;
    }
    uint8_t key[32];
    get_rand(key,32);
    time_t t=time(NULL);
    //print_time(t);
    write(F,&t,sizeof(time_t));
    write(F,key,32);
    close(F);
}

int check_keyfile(uint8_t* key)
{
    int F=open("key",O_RDONLY);
    if(F<0)
    {
        printf("key didnt open\n");
        return 0;
    }
    uint8_t buf[8];
    time_t t;
    if(read(F,&t,sizeof(time_t))!=8)
    {
        printf("cant read time\n");
        close(F);
        return 0;
    }
    //t=atoi(buf);
    if(check(t))
    {
        if(read(F,key,32)!=32)
        {
            printf("key is short\n");
            return 0;
        }
        close(F);
        return 1;
    }
    printf("key is old\n");
    close(F);
    return 0;
}

int main(int argc,char* argv[])
{
    if(!test())
    {
        log("tests failed");
        printf("tests failed\n");
        log("session end\n");
        return 0;
    }
    else
    {
        log("tests completed");
        printf("tests completed\n");
    }
    if(argc==2)
    {
        gen_keyfile();
    }
    else if(argc!=3)
    {
        printf("enter KEY and FILE\n");
        return 0;
    }
    if(auth()==0)
    {
        return 0;   
    }
    int fd=open("a.out",O_RDONLY);
    uint8_t h[32];
    get_h(fd,h);
    uint8_t h2[32];
    close(fd);
    fd=open("integ",O_RDONLY);
    read(fd,h2,32);
    close(fd);
    if(compare_arrays(h,h2,32)==0)
    {
        printf("wrong exe file\n");
        log("exe file is not valid");
        log("session end\n");
        return 0;
    }
    else
    {
        log("exe file valid");
    }
    uint8_t key[32];
    if(check_keyfile(key)==0)
    {
        log("key is old");
        return 0;
    }
    log("key is good");
    int i=1;
    if(argc!=2)
    {
        i=2;
    }

    printf("%s ",argv[i]);
    alg(key,argv[i]);
    //alg(argv[1],argv[2]);
    return 0;
}