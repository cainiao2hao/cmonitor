#include "mydialog.h"
int sortType, direction;
MyDialog::MyDialog(QWidget* parent) : QDialog(parent)
{
    /********获取系统内存总数*****/
    FILE* f = fopen("/proc/meminfo", "r");
    char ss[30];
    fgets(ss, 30, f);
    fclose(f);
    sscanf(ss, "MemTotal: %d", &TOTALMEM);
    /**********定时器***********/
    QTimer* iTimer = new QTimer(this);
    connect(iTimer, SIGNAL(timeout()), this, SLOT(updateTab()));
    iTimer->start(1000); //500ms更新

    tabWidget = new QTabWidget();
    /**********进程信息***********/
    now = 0, pre = 1;
    process[now] = new vector<ProcessNode>;
    process[pre] = new vector<ProcessNode>;
    /***************************/
    pcap_t *handle;
    tabProcess = new QTableWidget();
    tabProcess->resize(1000, 500);
    tabProcess->setColumnCount(10);
    QStringList header; //表头信息
    header << "PID" << "USER" << "NI" << "MEM(KB)" << "S" << "MEM%" << "CPU%" << "COMMAN" << "Down(KB/s)" << "Up(KB/s)";
    tabProcess->setHorizontalHeaderLabels(header);
    tabProcess->setEditTriggers(QAbstractItemView::NoEditTriggers); //禁止编辑
    tabProcess->setSelectionBehavior(QAbstractItemView::SelectRows); //整行选中
    tabProcess->setSelectionMode(QAbstractItemView::SingleSelection); //单选
    connect(tabProcess->horizontalHeader(), SIGNAL(sectionClicked(int)), this, SLOT(mySort(int))); //点击排序

    tabProcess->setContextMenuPolicy(Qt::CustomContextMenu); //右键时显示菜单
    connect(tabProcess, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(rightClick(QPoint)));
    popMenu = new QMenu(tabProcess);
    killProcess = popMenu->addAction(QString::fromUtf8("结束进程"));
    connect(killProcess, SIGNAL(triggered(bool)), this, SLOT(doKill()));

    QScrollArea scrollArea; //滚动条
    scrollArea.setWidget(tabProcess);
    sortType = direction = 0; //初始按照pid排序
    tabWidget->addTab(tabProcess, QString::fromUtf8("进程信息"));

    QHBoxLayout* layout = new QHBoxLayout();
    layout->addWidget(tabWidget);

    this->setLayout(layout);
    this->resize(1000, 500);
    this->setWindowTitle("CMonitor");
}
void MyDialog::rightClick(QPoint pos)
{ //右键时在点击的地方显示菜单
    popMenu->exec(QCursor::pos());
}
void MyDialog::doKill()
{ //杀死一个进程
    li = tabProcess->selectionModel()->selectedRows();
    int row = li[0].row();
    it = tabProcess->item(row, 0);
    char com[20];
    sprintf(com, "kill %d", it->text().toInt());
    system(com);
}
void MyDialog::mySort(int x)
{ //单击表头时修改排序方式
    sortType = x;
    direction ^= 1;
}
void MyDialog::updateTab()
{ //更新进程表
    updateProcess();
    tabProcess->setRowCount(process[now]->size());
    for (int i = 0; i < process[now]->size(); i++)
    {
        tabProcess->setItem(i, 0, new QTableWidgetItem(QString::number((*process[now])[i].pid)));
        tabProcess->setItem(i, 1, new QTableWidgetItem((*process[now])[i].UserName));
        tabProcess->setItem(i, 2, new QTableWidgetItem(QString::number((*process[now])[i].pr)));
        tabProcess->setItem(i, 3, new QTableWidgetItem(QString::number((*process[now])[i].mem)));
        tabProcess->setItem(i, 4, new QTableWidgetItem(QString((*process[now])[i].state)));
        tabProcess->setItem(i, 5, new QTableWidgetItem(QString::number((*process[now])[i].memp)));
        tabProcess->setItem(i, 6, new QTableWidgetItem(QString::number((*process[now])[i].cpup)));
        tabProcess->setItem(i, 7, new QTableWidgetItem((*process[now])[i].ProName));
        tabProcess->setItem(i, 8, new QTableWidgetItem(QString::number((*process[now])[i].in_speed)));
        tabProcess->setItem(i, 9, new QTableWidgetItem(QString::number((*process[now])[i].out_speed)));
    }
}
bool operator<(ProcessNode a, ProcessNode b)
{
    //根据sortType和direction比较两个进程
    switch (sortType)
    {
        case 0:
            return direction ? a.pid < b.pid : a.pid > b.pid;
        case 1:
            return direction ? strcmp(a.UserName, b.UserName) < 0 : strcmp(a.UserName, b.UserName) > 0;
        case 2:
            return direction ? a.pr < b.pr : a.pr > b.pr;
        case 3:
            return direction ? a.mem < b.mem : a.mem > b.mem;
        case 4:
            return direction ? a.state < b.state : a.state > b.state;
        case 5:
            return direction ? a.memp - b.memp < -EPS : a.memp - b.memp > EPS;
        case 6:
            return direction ? a.cpup - b.cpup < -EPS : a.cpup - b.cpup > EPS;
        case 7:
            return direction ? strcmp(a.ProName, b.ProName) < 0 : strcmp(a.ProName, b.ProName) > 0;
        case 8:
            return direction ? a.in_speed - b.in_speed<-EPS : a.in_speed - b.in_speed>EPS;
        case 9:
            return direction ? a.out_speed - b.out_speed<-EPS : a.out_speed - b.out_speed>EPS;
    }
}
void MyDialog::updateProcess()
{
    //从/proc中读取进程信息
    struct dirent** namelist;
    int n = 0;
    swap(now, pre);
    process[now]->clear();
    n = scandir("/proc", &namelist, 0, alphasort);
    while (n--)
    {
        if (namelist[n]->d_name[0] >= '0' && namelist[n]->d_name[0] <= '9')
        {
            int x, flag = 0;
            sscanf(namelist[n]->d_name, "%d", &x);
            for (int i = 0; i < process[pre]->size(); i++)
                if ((*process[pre])[i].pid == x)
                {
                    flag = 1;
                    ProcessNode tmp = (*process[pre])[i];
                    tmp.fresh();
                    process[now]->push_back(tmp);
                    break;
                }
            if (!flag)
                process[now]->push_back(ProcessNode(namelist[n]->d_name));
        }
        free(namelist[n]);
    }
    if (namelist)
        free(namelist);
    sort(process[now]->begin(), process[now]->end());
}
