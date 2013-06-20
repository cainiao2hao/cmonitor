#include <grab-packet.h>
void forceExit(string ch)
{
    cout << ch << endl;
    exit(0);
}
local_addr * local_addrs;
void getLocal(const char *device)
{
    /* get local IPv4 addresses */
    int sock;
    struct ifreq iFreq;
    //iFreq用来保存某个接口的信息
    //--http://blog.csdn.net/vc0051127833/article/details/7029556
    struct sockaddr_in *saddr;
    if ((sock = socket(AF_INET, SOCK_RAW, htons(0x0806))) < 0)
    {
        forceExit("creating socket failed while establishing local IP - are you root?");
    }
    strcpy(iFreq.ifr_name, device); //把网卡（device）的名字复制到iFreq的name变量
    if (ioctl(sock, SIOCGIFADDR, &iFreq) < 0)
    { //获取接口地址,0->成功,-1->出错,改变iFreq,记录网卡的信息
        //--http://www.iteye.com/topic/309442
        forceExit("ioctl failed while establishing local IP for selected device %s. You may specify the device on the command line.");
    }
    saddr = (struct sockaddr_in*) &iFreq.ifr_addr;
    local_addrs = new local_addr(saddr->sin_addr.s_addr);
}
map<string, int> hash2inode;
map<int, Total> inode2trafic;
Packet pack;
void addtohash2inode(char * buffer)
{
    short int sa_family;
    struct in6_addr result_addr_local;
    struct in6_addr result_addr_remote;

    char rem_addr[128], local_addr[128];
    int local_port, rem_port;
    struct in6_addr in6_local;
    struct in6_addr in6_remote;
    // this leaked memory
    //unsigned long * inode = (unsigned long *) malloc (sizeof(unsigned long));
    unsigned long inode;

    int matches = sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X %*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
            local_addr, &local_port, rem_addr, &rem_port, &inode);

    if (matches != 5)
    {
        fprintf(stderr, "Unexpected buffer: '%s'\n", buffer);
        exit(0);
    }

    if (inode == 0)
    {
        /* connection is in TIME_WAIT state. We rely on 
         * the old data still in the table. */
        return;
    }

    if (strlen(local_addr) > 8)
    {
        /* this is an IPv6-style row */
        /* not supposed yet*/
        /* Demangle what the kernel gives us */
        sscanf(local_addr, "%08X%08X%08X%08X",
                &in6_local.s6_addr32[0], &in6_local.s6_addr32[1],
                &in6_local.s6_addr32[2], &in6_local.s6_addr32[3]);
        sscanf(rem_addr, "%08X%08X%08X%08X",
                &in6_remote.s6_addr32[0], &in6_remote.s6_addr32[1],
                &in6_remote.s6_addr32[2], &in6_remote.s6_addr32[3]);

        if ((in6_local.s6_addr32[0] == 0x0) && (in6_local.s6_addr32[1] == 0x0)
                && (in6_local.s6_addr32[2] == 0xFFFF0000))
        {
            /* IPv4-compatible address */
            result_addr_local = *((struct in6_addr*) &(in6_local.s6_addr32[3]));
            result_addr_remote = *((struct in6_addr*) &(in6_remote.s6_addr32[3]));
            sa_family = AF_INET;
        } else
        {
            /* real IPv6 address */
            /* not ready yet*/
            //            return;
            //inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &localaddr);
            //inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
            //INET6_getsock(addr6, (struct sockaddr *) &remaddr);
            //localaddr.sin6_family = AF_INET6;
            //remaddr.sin6_family = AF_INET6;
            result_addr_local = in6_local;
            result_addr_remote = in6_remote;
            sa_family = AF_INET6;
        }
        //        return;
    } else
    {
        /* this is an IPv4-style row */
        sscanf(local_addr, "%X", (unsigned int *) &result_addr_local);
        sscanf(rem_addr, "%X", (unsigned int *) &result_addr_remote);
        sa_family = AF_INET;
    }

    char * hashkey = (char *) malloc(50 * sizeof (char));
    char * local_string = (char*) malloc(50);
    char * remote_string = (char*) malloc(50);
    inet_ntop(sa_family, &result_addr_local, local_string, 49);
    inet_ntop(sa_family, &result_addr_remote, remote_string, 49);

    snprintf(hashkey, 60 * sizeof (char), "%s:%d-%s:%d", local_string, local_port, remote_string, rem_port);
    free(local_string);
    //    cout << "map " << hashkey << " to " << inode << endl;
    hash2inode[hashkey] = inode;
    if (inode2trafic.find(inode) != inode2trafic.end())
        inode2trafic[inode].vivid = true;
    /* workaround: sometimes, when a connection is actually from 172.16.3.1 to
     * 172.16.3.3, packages arrive from 195.169.216.157 to 172.16.3.3, where
     * 172.16.3.1 and 195.169.216.157 are the local addresses of different 
     * interfaces */
    struct local_addr * current_local_addr = local_addrs;

    snprintf(hashkey, 60 * sizeof (char), "%s:%d-%s:%d", current_local_addr->string, local_port, remote_string, rem_port);
    hash2inode[hashkey] = inode;

    free(hashkey);
    free(remote_string);
}
void fresh_hash2inode_table() //also fresh inode2trafic table
{
    hash2inode.clear();
    FILE * procinfo = fopen("/proc/net/tcp", "r");
    char buffer[8192];
    if (procinfo == NULL)
        return;
    fgets(buffer, sizeof (buffer), procinfo);
    do
    {
        if (fgets(buffer, sizeof (buffer), procinfo))
            addtohash2inode(buffer);
    } while (!feof(procinfo));
    fclose(procinfo);
    procinfo = fopen("/proc/net/tcp6", "r");
    if (procinfo == NULL)
        return;
    fgets(buffer, sizeof (buffer), procinfo);
    do
    {
        if (fgets(buffer, sizeof (buffer), procinfo))
            addtohash2inode(buffer);
    } while (!feof(procinfo));
    fclose(procinfo);

    for (map<int, Total>::iterator it = inode2trafic.begin(); it != inode2trafic.end();)
    {
        if (!(it->second.vivid))
            inode2trafic.erase(it++);
        else it->second.vivid = false, it++;
    }
}
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    EtherHdr *ether = new EtherHdr();
    IpHdr *iphdr = new IpHdr();
    TcpHdr *tcphdr = new TcpHdr();
    *ether = *((EtherHdr*) packet);
    *iphdr = *((IpHdr *) (packet + 14));
    *tcphdr = *((TcpHdr*) (packet + 34));
    if (ether->ether_type == 0x0008) //ipv4
    {
        if (iphdr->protocol == IPPROTO_TCP) //tcp
        {
            pack.size = header->len;
            inet_ntop(AF_INET, &iphdr->saddr, pack.src_addr, 20);
            inet_ntop(AF_INET, &iphdr->daddr, pack.des_addr, 20);
            if (iphdr->daddr == local_addrs->addr)
                pack.direction = IN;
            else pack.direction = OUT;
            //            if (iphdr->saddr == local_addrs->addr) //判断包的方向
            //                pack.direction = OUT;
            //            else if (iphdr->daddr == local_addrs->addr)
            //                pack.direction = IN;
            //            else pack.direction = -1;
            //            assert(pack.direction != -1);

            pack.src_port = ntohs(tcphdr->th_sport);
            pack.des_port = ntohs(tcphdr->th_dport);
            //            cout << pack.src_port << "  " << pack.des_port << endl;
            //    fprintf(stderr, "%s:%d-%s:%d\n", pack.src_addr, pack.src_port, pack.des_addr, pack.des_port);
            if (pack.direction == OUT)
                sprintf(pack.hash, "%s:%d-%s:%d", pack.src_addr, pack.src_port, pack.des_addr, pack.des_port);
            else sprintf(pack.hash, "%s:%d-%s:%d", pack.des_addr, pack.des_port, pack.src_addr, pack.src_port);
            if (hash2inode.find(pack.hash) == hash2inode.end())
                fresh_hash2inode_table();
            if (hash2inode.find(pack.hash) == hash2inode.end())
            {
                cout << "can't find this packet hash " << pack.hash << " after fresh the hash to inode table" << endl;
                return;
            }
            cout << "hit !  size is " << pack.size << endl;
            if (pack.direction == OUT)
                inode2trafic[hash2inode[pack.hash]].out += pack.size;
            else inode2trafic[hash2inode[pack.hash]].in += pack.size;

        }
    }
    delete ether;
    delete iphdr;
    delete tcphdr;
}
void* begingrab(void *)
{
    char dev[10];
    strcpy(dev, "wlan0"); //本机测试使用无线网
    char errbuf[PCAP_ERRBUF_SIZE]; //出错信息
    cout << "DEV: " << dev << endl;
    bpf_u_int32 mask; //网络掩码
    bpf_u_int32 net; //网络号
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    { //获取网卡的网络号和掩码
        cout << "can't get netmask for device" << dev << endl;
        strcpy(dev, "eth0");
        cout << "trying device eth0" << endl;
        cout << "DEV: " << dev << endl;
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        {
            cout << "can't get netmask for device" << dev << endl;
            exit(0);
        }
    }
    pcap_t* handle;
    handle = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf); //打开网络设备
    if (handle == NULL)
    {
        cout << "can't open device " << dev << endl;
        exit(0);
    }
    getLocal(dev); //获取本机ip
    char filter[100];
    sprintf(filter, "host %s", local_addrs->string); //构造过滤器，只考虑本机ip
    bpf_program fp;
    //    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    //    { //编译过滤器
    //        cout << "compile filter error ! " << endl;
    //        exit(0);
    //    }
    //    if (pcap_setfilter(handle, &fp) == -1)
    //    { //应用过滤器
    //        cout << "set filter error ! " << endl;
    //        exit(0);
    //    }
    while (1)
    {
        bool get_a_packet = false;
        int ret = pcap_dispatch(handle, -1, got_packet, NULL);
        if (ret == -1 || ret == -2)
        {
            cout << "error occur when grab a packet!" << endl;
        } else if (ret != 0)
            get_a_packet = true;
        if (!get_a_packet) //降低CPU利用率 >_<
            usleep(100);
    }
    pcap_close(handle);
    return NULL;
}