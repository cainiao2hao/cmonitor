#include "ProcessNode.h"
int TOTALMEM;
extern map<int, Total> inode2trafic;
ProcessNode::ProcessNode()
{
}
ProcessNode::ProcessNode(char* s)
{
    sscanf(s, "%d", &pid);
    sprintf(path, "/proc/%s", s);
    memset(cputime, -1, sizeof (cputime));
    pos = 0;
    memset(in, -1, sizeof (in));
    memset(out, -1, sizeof (out));
    p = intotal = outtotal = 0;
    in_speed = out_speed = 0;
    fresh();
}
unsigned long str2ulong(char * ptr)
{
    unsigned long retval = 0;
    while ((*ptr >= '0') && (*ptr <= '9'))
    {
        retval *= 10;
        retval += *ptr - '0';
        ptr++;
    }
    return retval;
}
void ProcessNode::get_info_by_linkname(char *linkname)
{
    if (strncmp(linkname, "socket:[", 8) == 0)
    {
        char * ptr = linkname + 8;
        unsigned long inode = str2ulong(ptr);
        if (inode2trafic.find(inode) == inode2trafic.end())
        {
            //            cout << "can't find inode " << inode << " in inode2trafic table!" << endl;
            return;
        }
//        cout << "find inode " << inode << " in inode2trafic table!" << endl;
        out[p] += inode2trafic[inode].out;
        in[p] += inode2trafic[inode].in;
        inode2trafic[inode].out = 0;
        inode2trafic[inode].in = 0;
    }
}
void ProcessNode::freshspeed()
{
    char *dirname = (char *) malloc(50 * sizeof (char));
    sprintf(dirname, "%s/fd", path);
    DIR * dir = opendir(dirname);
    if (!dir)
    {
        cout << "Couldn't open dir " << dirname << endl;
        free(dirname);
        return;
    }
    dirent * entry;
    while ((entry = readdir(dir)))
    {
        if (entry->d_type != DT_LNK)
            continue;
        int fromlen = 50 + strlen(entry->d_name) + 1;
        char * fromname = (char *) malloc(fromlen * sizeof (char));
        snprintf(fromname, fromlen, "%s/%s", dirname, entry->d_name);
        int linklen = 80;
        char linkname [linklen];
        int usedlen = readlink(fromname, linkname, linklen - 1);
        if (usedlen == -1)
        {
            free(fromname);
            continue;
        }
        assert(usedlen < linklen);
        linkname[usedlen] = '\0';
        //std::cout << "Linking to: " << linkname << std::endl;
        get_info_by_linkname(linkname);
        free(fromname);
    }
    closedir(dir);
    free(dirname);
}
void ProcessNode::fresh()
{
    char status[40][50], cmd[30];
    sprintf(cmd, "%s/status", path);
    FILE* f;
    f = fopen(cmd, "r");
    if (f == NULL)
    {
        fprintf(stdout, "pid: %d can't open status\n", pid);
        return;
    } else
    {
        for (int i = 1; i <= 37; i++)
            fgets(status[i], 50, f);
        fclose(f);
    }//读取进程的status
    sscanf(status[1], "Name: %s", ProName); //get process name
    sscanf(status[2], "State: %c", &state); //get process state
    if (status[12][0] != 'V') //get process memory size
        mem = 0;
    else sscanf(status[16], "VmRSS: %d", &mem);
    sscanf(status[7], "Uid: %d", &uid); //get user id
    struct passwd* pw; //get user name
    pw = getpwuid(uid);
    if (pw)
        strcpy(UserName, pw->pw_name);
    pr = getpriority(PRIO_PROCESS, pid); //get priority
    memp = mem * 100.0 / TOTALMEM; //get mem%
    /************get cpu%**5次取平均**************/
    //取当前进程的总时间（用户态+内核态）
    int utime, stime, protime;
    char val[50];
    sprintf(cmd, "%s/stat", path);
    f = fopen(cmd, "r");
    for (int i = 0; i < 14; i++)
        fscanf(f, "%s", val);
    sscanf(val, "%d", &utime);
    fscanf(f, "%s", val);
    sscanf(val, "%d", &stime);
    protime = utime + stime;
    fclose(f);
    //取cpu总时间
    int systime = 0, tmp;
    strcpy(cmd, "/proc/stat");
    f = fopen(cmd, "r");
    fscanf(f, "%s", val);
    for (int i = 0; i < 8; i++)
    {
        fscanf(f, "%d", &tmp);
        systime += tmp;
    }
    systime /= 4; //4核
    fclose(f);
    //计算cpu%
    if (cputime[SYS][pos] == -1)
        cpup = protime * 100 / systime;
    else cpup = (protime - cputime[PRO][pos]) * 100 / (systime - cputime[SYS][pos]);
    cputime[PRO][pos] = protime;
    cputime[SYS][pos] = systime;
    pos = (pos + 1) % 5;
    //更新流量信息
    if (in[p] != -1)
    {
        intotal -= in[p];
        outtotal -= out[p];
    }
    in[p] = out[p] = 0;
    freshspeed();
    intotal += in[p];
    outtotal += out[p];
    p = (p + 5) % 5;
    in_speed = intotal / 5.0 / 1024;
    out_speed = outtotal / 5.0 / 1024;
}
