#ifndef MYDIALOG_H
#define MYDIALOG_H
#include <QMenu>
#include <QDialog>
#include <QtGui/QTabWidget>
#include <QtGui/QHBoxLayout>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QScrollArea>
#include <QString>
#include <algorithm>
#include <QHeaderView>
#include <QAction>
#include <QHeaderView>
#include <QtGui/QLineEdit>
#include <QtGui/QPushButton>
#include <QtGui/QWidget>
#include <QTimer>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <ProcessNode.h>
#include <cstdio>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <set>
#include <iostream>
#include <map>
#include <time.h>
#include <stdlib.h>
#include <vector>
#include <algorithm>
#include <cmath>
#include <grab-packet.h>
#include <pcap.h>
#define EPS 1e-8
using namespace std;
class QTabWidget;
class MyDialog : public QDialog
{
    Q_OBJECT
public:
    explicit MyDialog(QWidget* parent = 0);
signals:
public slots:
    void updateProcess();
    void updateTab();
    void mySort(int x);
    void rightClick(QPoint pos);
    void doKill();
private:
    int now,pre;
    vector<ProcessNode> *process[2];
    QTableWidget* tabProcess;
    QTabWidget* tabWidget;
    QModelIndexList li;
    QTableWidgetItem *it;
    QMenu *popMenu;
    QAction *killProcess;
};
#endif // MYDIALOG_H
