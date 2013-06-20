#pragma once
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <pwd.h>
#include<sys/time.h>
#include<sys/resource.h>
#include <map>
#include "grab-packet.h"
#include <dirent.h>
using namespace std;

#define SYS 0
#define PRO 1
extern int TOTALMEM;

class ProcessNode
{
public:
    char path[20], UserName[20], ProName[20], state;
    int pid, uid, mem, pr, totalmem;
    int cputime[2][5], pos, cpup;
    int in[5], out[5], p, intotal, outtotal;
    double memp, in_speed, out_speed;
    ProcessNode(char* s);
    ProcessNode();
    void freshspeed();
    void get_info_by_linkname(char * linkname);
    void fresh();
};

